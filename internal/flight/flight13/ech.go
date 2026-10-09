// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"slices"

	"github.com/pion/dtls/v4/internal/ech"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/internal/negotiation"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

// acceptECH verifies the confirmation over the exact received ServerHello,
// then selects the inner offer for all subsequent negotiation checks.
// https://www.rfc-editor.org/rfc/rfc9849#section-6.1.4
func (h *handshakeContext) acceptECH(item dtlsflight.DecodedHandshakeCacheItem) error {
	context := h.state.ECH
	if context == nil || context.Accepted {
		return nil
	}
	if err := item.Validate(); err != nil {
		return err
	}
	hello, ok := item.Parsed.Message.(*handshake.MessageServerHello)
	if !ok || IsHelloRetryRequest(hello) {
		return echFailure(alert.IllegalParameter, ech.ErrUnsupported)
	}
	if err := h.verifyECHServerHello(hello, item.Raw.Data[handshake.HeaderLength:]); err != nil {
		return err
	}
	if err := h.selectECHInnerOffer(context.Inner); err != nil {
		return err
	}
	context.Accepted = true

	return nil
}

func (h *handshakeContext) verifyECHServerHello(hello *handshake.MessageServerHello, body []byte) error {
	suite, failure, err := selectServerHelloCipherSuite(hello, h.cfg)
	if err != nil {
		return echFailure(failure.Description, err)
	}
	confirmation, err := ech.AcceptanceConfirmation(suite.HashFunc(), h.state.ECH.Inner, body)
	if err != nil {
		return echFailure(alert.IllegalParameter, err)
	}
	if subtle.ConstantTimeCompare(confirmation, body[26:34]) != 1 {
		// Authenticated rejection and retry configs are not implemented yet.
		return echFailure(alert.InternalError, ech.ErrUnsupported)
	}
	// An accepting ServerHello carries confirmation only in its random field.
	if slices.ContainsFunc(hello.Extensions, func(ext extension.Value) bool {
		return ext.ExtensionType() == extension.TypeEncryptedClientHello
	}) {
		return echFailure(alert.UnsupportedExtension, ech.ErrInvalid)
	}

	return nil
}

func (h *handshakeContext) selectECHInnerOffer(body []byte) error {
	var inner handshake.MessageClientHello
	if err := inner.Unmarshal(body); err != nil {
		return err
	}
	var snapshots negotiation.ClientHelloSnapshots
	header := handshake.Header{Type: handshake.TypeClientHello, Length: uint32(len(body)), FragmentLength: uint32(len(body))} //nolint:gosec // ECH hello lengths are bounded by their wire vectors.
	wire, err := header.Marshal()
	if err != nil {
		return err
	}
	if err := snapshots.RecordWire(append(wire, body...)); err != nil {
		return err
	}
	h.state.LocalClientHelloSnapshots = snapshots
	h.state.LocalRandom = inner.Random

	return nil
}

// processECHClientHello produces a separate logical cache item, leaving the
// received outer in the retransmission cache untouched.
func (h *handshakeContext) processECHClientHello(item dtlsflight.DecodedHandshakeCacheItem) (dtlsflight.DecodedHandshakeCacheItem, error) {
	if err := item.Validate(); err != nil {
		return item, err
	}
	context, err := h.echClientHello(item.Raw.Data[handshake.HeaderLength:])
	if err != nil || context.Inner == nil {
		return item, err
	}
	inner := &handshake.MessageClientHello{}
	if err = inner.Unmarshal(context.Inner); err != nil {
		return item, echFailure(alert.IllegalParameter, err)
	}
	for _, ext := range inner.Extensions {
		switch ext.ExtensionType() {
		case extension.TypePreSharedKey, extension.TypeEarlyData:

			return item, echFailure(alert.IllegalParameter, ech.ErrUnsupported)
		default:
		}
	}
	parsed := &handshake.Handshake{Header: item.Parsed.Header, Message: inner}
	// Typed parsers can discard unknown fields.
	parsed.Header.Length = uint32(len(context.Inner)) //nolint:gosec
	parsed.Header.FragmentOffset = 0
	parsed.Header.FragmentLength = parsed.Header.Length
	data, err := parsed.Header.Marshal()
	if err != nil {
		return item, err
	}
	data = append(data, context.Inner...)
	raw := dtlsflight.HandshakeCacheItem{Typ: item.Raw.Typ, IsClient: item.Raw.IsClient, Epoch: item.Raw.Epoch, MessageSequence: item.Raw.MessageSequence, Data: data}
	h.state.ECHServer = &context

	return dtlsflight.DecodedHandshakeCacheItem{Raw: &raw, Parsed: parsed}, nil
}

func (h *handshakeContext) echClientHello(body []byte) (ech.ServerContext, error) {
	if context := h.state.ECHServer; context != nil && len(context.HelloRetryRequest) != 0 {
		_, err := context.ProcessRetry(body)

		return *context, err
	}

	return ech.ProcessClientHello(body, h.cfg.ECHKeys)
}

func (h *handshakeContext) confirmECHRetry(serverHello *handshake.MessageServerHello) error {
	context := h.state.ECHServer
	if context == nil {
		return nil
	}
	ext := &extension13.ECHHelloRetryRequest{}
	serverHello.Extensions = append(serverHello.Extensions, ext)
	body, err := serverHello.Marshal()
	if err != nil {
		return err
	}
	if context.InitialInner == nil {
		context.InitialInner = bytes.Clone(context.Inner)
	}
	confirmation, err := ech.RetryConfirmation(h.state.CipherSuite.HashFunc(), context.InitialInner, body)
	if err != nil {
		return err
	}
	copy(ext.Confirmation[:], confirmation)
	context.HelloRetryRequest, err = serverHello.Marshal()

	return err
}

func echFailure(description alert.Description, err error) error {
	return errors.Join(err, &alert.Alert{Level: alert.Fatal, Description: description})
}

func (h *handshakeContext) confirmECH(serverHello *handshake.MessageServerHello) error {
	if h.state.ECHServer == nil {
		return nil
	}
	body, err := serverHello.Marshal()
	if err != nil {
		return err
	}
	confirmation, err := h.state.ECHServer.Confirmation(h.state.CipherSuite.HashFunc(), body)
	if err != nil {
		return err
	}
	copy(serverHello.Random.RandomBytes[handshake.RandomBytesLength-8:], confirmation)
	h.state.LocalRandom = serverHello.Random

	return nil
}
