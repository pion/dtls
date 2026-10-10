// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"hash"
	"slices"

	"github.com/pion/dtls/v4/internal/ech"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/internal/negotiation"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"golang.org/x/crypto/cryptobyte"
)

// acceptECH verifies confirmation over the exact received ServerHello or HRR,
// then selects the accepted inner or rejected outer offer for negotiation checks.
// https://www.rfc-editor.org/rfc/rfc9849#section-6.1.4
func (h *handshakeContext) acceptECH(item dtlsflight.DecodedHandshakeCacheItem) error {
	context := h.state.ECH
	if context == nil {
		return nil
	}
	if err := item.Validate(); err != nil {
		return err
	}
	hello, ok := item.Parsed.Message.(*handshake.MessageServerHello)
	if !ok {
		return echFailure(alert.IllegalParameter, ech.ErrUnsupported)
	}
	previouslyDecided := context.Accepted || context.Rejected
	if err := h.verifyECHServerHello(hello, item.Raw.Data[handshake.HeaderLength:]); err != nil {
		return err
	}
	if previouslyDecided {
		return nil
	}
	if context.Rejected {
		return h.selectECHOffer(context.Outer)
	}

	return h.selectECHOffer(context.Inner)
}

func (h *handshakeContext) verifyECHServerHello(hello *handshake.MessageServerHello, body []byte) error {
	suite, failure, err := selectServerHelloCipherSuite(hello, h.cfg)
	if err != nil {
		return echFailure(failure.Description, err)
	}
	if IsHelloRetryRequest(hello) {
		return h.verifyECHRetry(suite.HashFunc(), body)
	}
	if h.state.ECH.Rejected {
		return nil
	}
	confirmation, err := h.state.ECH.Confirmation(suite.HashFunc(), body)
	if err != nil {
		return echFailure(alert.IllegalParameter, err)
	}
	if subtle.ConstantTimeCompare(confirmation, body[26:34]) != 1 {
		if h.state.ECH.Accepted {
			return echFailure(alert.IllegalParameter, ech.ErrInvalid)
		}
		h.state.ECH.Rejected = true

		return nil
	}
	// An accepting ServerHello carries confirmation only in its random field.
	if slices.ContainsFunc(hello.Extensions, func(ext extension.Value) bool {
		return ext.ExtensionType() == extension.TypeEncryptedClientHello
	}) {
		return echFailure(alert.UnsupportedExtension, ech.ErrInvalid)
	}

	h.state.ECH.Accepted = true

	return nil
}

func (h *handshakeContext) verifyECHRetry(hashFunc func() hash.Hash, body []byte) error {
	err := h.state.ECH.AcceptRetry(hashFunc, body)
	// A missing or mismatched signal selects the outer handshake.
	if errors.Is(err, ech.ErrUnsupported) {
		h.state.ECH.Rejected = true
	} else if err != nil {
		return echFailure(alert.IllegalParameter, err)
	}

	return nil
}

func (h *handshakeContext) selectECHOffer(body []byte) error {
	var hello handshake.MessageClientHello
	if err := hello.Unmarshal(body); err != nil {
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
	h.state.LocalRandom = hello.Random

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

func (h *handshakeContext) appendECHRetryConfigs(exts []extension.Value) ([]extension.Value, error) {
	if h.state.ECHServer != nil || !h.state.RemoteClientHelloSnapshots.Initial().Offered(extension.TypeEncryptedClientHello) {
		return exts, nil
	}
	var builder cryptobyte.Builder
	builder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, key := range h.cfg.ECHKeys {
			if !key.SendAsRetry {
				continue
			}
			if _, _, err := ech.ParseConfig(key.Config); err != nil {
				b.SetError(err)

				return
			}
			b.AddBytes(key.Config)
		}
	})
	configs, err := builder.Bytes()
	if err != nil {
		return nil, err
	}
	if len(configs) > 2 {
		exts = append(exts, &extension13.ECHRetryConfigs{ConfigList: configs})
	}

	return exts, nil
}
