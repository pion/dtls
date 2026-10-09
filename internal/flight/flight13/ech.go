// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"errors"

	"github.com/pion/dtls/v4/internal/ech"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

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
