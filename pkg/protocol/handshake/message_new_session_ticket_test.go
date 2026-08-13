// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageNewSessionTicket(t *testing.T) {
	maxEarlyData := uint32(128)
	message := &MessageNewSessionTicket{
		TicketLifetime: 0x01020304,
		TicketAgeAdd:   0x05060708,
		TicketNonce:    []byte{0xaa, 0xbb},
		Ticket:         []byte{0xcc, 0xdd, 0xee},
		Extensions: []extension.Value{
			&extension13.MaxEarlyData{Size: maxEarlyData},
		},
	}
	want := []byte{
		0x01, 0x02, 0x03, 0x04, // ticket_lifetime
		0x05, 0x06, 0x07, 0x08, // ticket_age_add
		0x02, 0xaa, 0xbb, // ticket_nonce
		0x00, 0x03, 0xcc, 0xdd, 0xee, // ticket
		0x00, 0x08, // extensions length
		0x00, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x80, // early_data
	}

	raw, err := message.Marshal()
	require.NoError(t, err)
	assert.Equal(t, want, raw)
	assert.Equal(t, TypeNewSessionTicket, message.Type())

	decoded := &MessageNewSessionTicket{}
	require.NoError(t, decoded.Unmarshal(want))
	assert.Equal(t, message, decoded)
}

func TestMessageNewSessionTicketEmptyVectors(t *testing.T) {
	message := &MessageNewSessionTicket{Ticket: []byte{0x01}}

	raw, err := message.Marshal()
	require.NoError(t, err)

	decoded := &MessageNewSessionTicket{}
	require.NoError(t, decoded.Unmarshal(raw))
	assert.Empty(t, decoded.TicketNonce)
	assert.Empty(t, decoded.Extensions)
}

func TestMessageNewSessionTicketMarshalErrors(t *testing.T) {
	tooManyExtensions := make([]extension.Value, 16384)
	for i := range tooManyExtensions {
		tooManyExtensions[i] = extension.Raw{Type: extension.TypePostHandshakeAuth}
	}

	tests := map[string]*MessageNewSessionTicket{
		"nonce too long": {TicketNonce: make([]byte, 256), Ticket: []byte{0x01}},
		"empty ticket":   {},
		"ticket too long": {
			Ticket: make([]byte, 65536),
		},
		"extensions too long": {
			Ticket:     []byte{0x01},
			Extensions: tooManyExtensions,
		},
	}

	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := message.Marshal()
			assert.Error(t, err)
		})
	}
}

func TestMessageNewSessionTicketUnmarshalErrors(t *testing.T) {
	valid := []byte{
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
		0x01, 0xaa,
		0x00, 0x01, 0xbb,
		0x00, 0x00,
	}
	tests := map[string][]byte{
		"too short":          valid[:12],
		"truncated nonce":    append(append([]byte(nil), valid[:9]...), 0x08, 0x00, 0x01, 0x02),
		"empty ticket":       append(append([]byte(nil), valid[:10]...), 0x00, 0x00, 0x00, 0x00),
		"truncated ticket":   append(append([]byte(nil), valid[:10]...), 0x00, 0x04, 0xbb, 0x00, 0x00),
		"invalid extensions": append(append([]byte(nil), valid[:13]...), 0x00, 0x01, 0xff),
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			message := &MessageNewSessionTicket{
				TicketLifetime: 42,
				Ticket:         []byte("preserved"),
			}
			err := message.Unmarshal(raw)
			assert.Error(t, err)
			assert.Equal(t, uint32(42), message.TicketLifetime)
			assert.Equal(t, []byte("preserved"), message.Ticket)
		})
	}

	assert.ErrorIs(t, (&MessageNewSessionTicket{}).Unmarshal(valid[:12]), dtlserrors.ErrBufferTooSmall)
}
