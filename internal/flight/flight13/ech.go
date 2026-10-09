// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"errors"

	"github.com/pion/dtls/v4/internal/ech"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

// processECHClientHello produces a separate logical cache item, leaving the
// received outer in the retransmission cache untouched.
func (h *handshakeContext) processECHClientHello(item dtlsflight.DecodedHandshakeCacheItem) (dtlsflight.DecodedHandshakeCacheItem, error) {
	if err := item.Validate(); err != nil {
		return item, err
	}
	context, err := ech.ProcessClientHello(item.Raw.Data[handshake.HeaderLength:], h.cfg.ECHKeys)
	if err != nil || context.Inner == nil {
		return item, err
	}
	inner := &handshake.MessageClientHello{}
	if err = inner.Unmarshal(context.Inner); err != nil {
		return item, echFailure(alert.IllegalParameter, err)
	}
	for _, ext := range inner.Extensions {
		switch ext.ExtensionType() {
		case extension.TypePreSharedKey, extension.TypeEarlyData, extension.TypeCookie:

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
	confirmation, err := ech.AcceptanceConfirmation(h.state.CipherSuite.HashFunc(), h.state.ECHServer.Inner, body)
	if err != nil {
		return err
	}
	copy(serverHello.Random.RandomBytes[handshake.RandomBytesLength-8:], confirmation)
	h.state.LocalRandom = serverHello.Random

	return nil
}
