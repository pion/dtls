// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake_test

import (
	"errors"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
)

func TestHandshakeMessage(t *testing.T) {
	rawHandshakeMessage := []byte{
		0x01, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0xfe, 0xfd, 0xb6,
		0x2f, 0xce, 0x5c, 0x42, 0x54, 0xff, 0x86, 0xe1, 0x24, 0x41, 0x91, 0x42, 0x62, 0x15, 0xad,
		0x16, 0xc9, 0x15, 0x8d, 0x95, 0x71, 0x8a, 0xbb, 0x22, 0xd7, 0x47, 0xec, 0xd8, 0x3d, 0xdc,
		0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random: handshake.Random{
			GMTUnixTime: time.Unix(3056586332, 0),
			RandomBytes: [28]byte{
				0x42, 0x54, 0xff, 0x86, 0xe1, 0x24, 0x41, 0x91, 0x42, 0x62, 0x15, 0xad, 0x16, 0xc9,
				0x15, 0x8d, 0x95, 0x71, 0x8a, 0xbb, 0x22, 0xd7, 0x47, 0xec, 0xd8, 0x3d, 0xdc, 0x4b,
			},
		},
		SessionID:          []byte{},
		Cookie:             []byte{},
		CipherSuiteIDs:     []uint16{},
		CompressionMethods: []*protocol.CompressionMethod{},
		Extensions:         []extension.Value{},
	}
	parsedHandshake := &handshake.Handshake{
		Header: handshake.Header{
			Length:         0x29,
			FragmentLength: 0x29,
			Type:           handshake.TypeClientHello,
		},
		Message: clientHello,
	}

	h := &handshake.Handshake{}
	assert.NoError(t, h.Unmarshal(rawHandshakeMessage))
	assert.Equal(t, parsedHandshake, h, "handshakeMessageClientHello unmarshal")

	raw, err := h.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawHandshakeMessage, raw, "handshakeMessageClientHello marshal")
}

func TestPostHandshakeMessageDispatch(t *testing.T) {
	maxEarlyData := uint32(128)
	newSessionTicket := &handshake.MessageNewSessionTicket{
		TicketLifetime: 1,
		TicketAgeAdd:   2,
		TicketNonce:    []byte{0x03},
		Ticket:         []byte{0x04},
		Extensions: []extension.Value{
			&extension13.MaxEarlyData{Size: maxEarlyData},
		},
	}
	tests := map[string]handshake.Message{
		"NewSessionTicket": newSessionTicket,
		"KeyUpdate": &handshake.MessageKeyUpdate{
			RequestUpdate: handshake.KeyUpdateRequested,
		},
		"NewConnectionID": &handshake.MessageNewConnectionID{
			CIDs:  [][]byte{{0x05}},
			Usage: handshake.ConnectionIDSpare,
		},
		"RequestConnectionID": &handshake.MessageRequestConnectionID{
			NumCIDs: 2,
		},
	}

	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			encoded, err := (&handshake.Handshake{Message: message}).Marshal()
			assert.NoError(t, err)

			decoded := &handshake.Handshake{}
			assert.NoError(t, decoded.Unmarshal(encoded))
			m1, _ := message.Marshal()
			m2, _ := decoded.Message.Marshal()
			assert.Equal(t, m1, m2)
		})
	}
}

type countingMessage struct {
	*handshake.MessageFinished
	err error
}

func (m *countingMessage) MarshalTo(out []byte) (int, error) {
	copy(out, []byte{1, 2})

	return 2, m.err
}

func TestHandshakeMarshalToReturnsChildByteCount(t *testing.T) {
	errMessage := errors.New("message marshal failed") //nolint:err113
	for name, messageErr := range map[string]error{"Success": nil, "MessageError": errMessage} {
		t.Run(name, func(t *testing.T) {
			message := &countingMessage{
				MessageFinished: &handshake.MessageFinished{VerifyData: make([]byte, 3)},
				err:             messageErr,
			}
			out := make([]byte, handshake.HeaderLength+message.MarshalSize())

			n, err := (&handshake.Handshake{Message: message}).MarshalTo(out)

			assert.ErrorIs(t, err, messageErr)
			assert.Equal(t, handshake.HeaderLength+2, n)
		})
	}
}
