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
	TicketLifetime uint32
	TicketAgeAdd   uint32
	TicketNonce    []byte
	Ticket         []byte
	Extensions     []extension.Extension
}

// Type returns the Handshake Type.
func (m MessageNewSessionTicket) Type() Type {
	return TypeNewSessionTicket
}

// Marshal encodes the Handshake.
func (m *MessageNewSessionTicket) Marshal() ([]byte, error) {
	if len(m.TicketNonce) > newSessionTicketMaxNonceLength {
		return nil, dtlserrors.ErrTicketNonceTooLong
	}
	if len(m.Ticket) == 0 || len(m.Ticket) > newSessionTicketMaxTicketLength {
		return nil, dtlserrors.ErrInvalidTicketLength
	}

	extensions, err := extension.Marshal(m.Extensions)
	if err != nil {
		return nil, err
	}
	if len(extensions)-2 > newSessionTicketMaxExtensionsLength {
		return nil, dtlserrors.ErrInvalidExtensionsLength
	}

	out := make([]byte, 0, 8+1+len(m.TicketNonce)+2+len(m.Ticket)+len(extensions))
	out = binary.BigEndian.AppendUint32(out, m.TicketLifetime)
	out = binary.BigEndian.AppendUint32(out, m.TicketAgeAdd)
	out = append(out, byte(len(m.TicketNonce))) //nolint:gosec // length is checked above
	out = append(out, m.TicketNonce...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.Ticket))) //nolint:gosec // length is checked above
	out = append(out, m.Ticket...)
	out = append(out, extensions...)

	return out, nil
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

	extensions, err := extension.Unmarshal(data[offset:])
	if err != nil {
		return err
	}

	m.TicketLifetime = ticketLifetime
	m.TicketAgeAdd = ticketAgeAdd
	m.TicketNonce = ticketNonce
	m.Ticket = ticket
	m.Extensions = extensions

	return nil
}
