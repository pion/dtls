// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

const (
	newSessionTicketMinLength           = 13
	newSessionTicketMaxNonceLength      = 255
	newSessionTicketMaxTicketLength     = 65535
	newSessionTicketMaxExtensionsLength = 65534
)

// MessageNewSessionTicket establishes a PSK that a client can use to resume a
// DTLS 1.3 connection.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.1
type MessageNewSessionTicket struct {
	TicketLifetime   uint32
	TicketAgeAdd     uint32
	TicketNonce      []byte
	Ticket           []byte
	CachedExtensions extension.CachedList
}

// Type returns the Handshake Type.
func (m MessageNewSessionTicket) Type() Type {
	return TypeNewSessionTicket
}

// MarshalSize returns the minimal size required for MarshalTo.
func (m *MessageNewSessionTicket) MarshalSize() int {
	return 8 + 1 + len(m.TicketNonce) + 2 + len(m.Ticket) + m.CachedExtensions.MarshalSize()
}

func (m MessageNewSessionTicket) Extensions() []extension.Value {
	return m.CachedExtensions.Values
}

// Marshal encodes the Handshake.
func (m *MessageNewSessionTicket) Marshal() ([]byte, error) {
	out := make([]byte, m.MarshalSize())
	_, err := m.MarshalTo(out)

	return out, err
}

// MarshalTo encodes the Handshake.
func (m *MessageNewSessionTicket) MarshalTo(out []byte) (int, error) {
	if len(out) < m.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}
	if len(m.TicketNonce) > newSessionTicketMaxNonceLength {
		return 0, dtlserrors.ErrTicketNonceTooLong
	}
	if len(m.Ticket) == 0 || len(m.Ticket) > newSessionTicketMaxTicketLength {
		return 0, dtlserrors.ErrInvalidTicketLength
	}

	n := 0
	binary.BigEndian.PutUint32(out[n:], m.TicketLifetime)
	n += 4
	binary.BigEndian.PutUint32(out[n:], m.TicketAgeAdd)
	n += 4
	out[n] = byte(len(m.TicketNonce)) //nolint:gosec // length is checked above
	n += 1
	n += copy(out[n:], m.TicketNonce)
	binary.BigEndian.PutUint16(out[n:], uint16(len(m.Ticket))) //nolint:gosec // length is checked above
	n += 2
	n += copy(out[n:], m.Ticket)
	nn, err := m.CachedExtensions.MarshalTo(out[n:])
	if err != nil {
		return n, err
	}
	if nn-2 > newSessionTicketMaxExtensionsLength {
		return n, dtlserrors.ErrInvalidExtensionsLength
	}

	return m.MarshalSize(), nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageNewSessionTicket) Unmarshal(data []byte) error {
	if len(data) < newSessionTicketMinLength {
		return dtlserrors.ErrBufferTooSmall
	}

	offset := 0
	ticketLifetime := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	ticketAgeAdd := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	nonceLength := int(data[offset])
	offset++
	if len(data)-offset < nonceLength+2 {
		return dtlserrors.ErrBufferTooSmall
	}
	ticketNonce := bytes.Clone(data[offset : offset+nonceLength])
	offset += nonceLength

	ticketLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if ticketLength == 0 {
		return dtlserrors.ErrInvalidTicketLength
	}
	if len(data)-offset < ticketLength+2 {
		return dtlserrors.ErrBufferTooSmall
	}
	ticket := bytes.Clone(data[offset : offset+ticketLength])
	offset += ticketLength

	extensions, err := decodeExtensionList(data[offset:], extensionContextNewSessionTicket)
	if err != nil {
		return err
	}

	m.TicketLifetime = ticketLifetime
	m.TicketAgeAdd = ticketAgeAdd
	m.TicketNonce = ticketNonce
	m.Ticket = ticket
	m.CachedExtensions = extension.CachedList{
		Values: extensions,
	}

	return nil
}
