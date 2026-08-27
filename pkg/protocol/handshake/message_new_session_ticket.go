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
	extensions     []extension.Value
}

// Type returns the Handshake Type.
func (m MessageNewSessionTicket) Type() Type {
	return TypeNewSessionTicket
}

// MarshalSize returns the minimal size required for MarshalTo.
func (m *MessageNewSessionTicket) MarshalSize() int {
	return 8 + 1 + len(m.TicketNonce) + 2 + len(m.Ticket) + extension.MarshalListSize(m.extensions)
}

func (m MessageNewSessionTicket) Extensions() []extension.Value {
	return m.extensions
}

// SetExtensions replaces the extensions.
func (m *MessageNewSessionTicket) SetExtensions(extensions []extension.Value) {
	m.extensions = extensions
}

// Marshal encodes the Handshake.
func (m *MessageNewSessionTicket) Marshal() ([]byte, error) {
	extensions, marshalSize, err := m.prepareMarshal()
	if err != nil {
		return nil, err
	}

	out := make([]byte, marshalSize)
	m.marshalTo(out, extensions)

	return out, nil
}

// MarshalTo encodes the Handshake.
func (m *MessageNewSessionTicket) MarshalTo(out []byte) (int, error) {
	extensions, marshalSize, err := m.prepareMarshal()
	if err != nil {
		return 0, err
	}
	if len(out) < marshalSize {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	m.marshalTo(out, extensions)

	return marshalSize, nil
}

func (m *MessageNewSessionTicket) prepareMarshal() ([]byte, int, error) {
	if len(m.TicketNonce) > newSessionTicketMaxNonceLength {
		return nil, 0, dtlserrors.ErrTicketNonceTooLong
	}
	if len(m.Ticket) == 0 || len(m.Ticket) > newSessionTicketMaxTicketLength {
		return nil, 0, dtlserrors.ErrInvalidTicketLength
	}
	extensions, err := extension.MarshalList(m.extensions)
	if err != nil {
		return nil, 0, err
	}
	if len(extensions)-2 > newSessionTicketMaxExtensionsLength {
		return nil, 0, dtlserrors.ErrInvalidExtensionsLength
	}

	marshalSize := 8 + 1 + len(m.TicketNonce) + 2 + len(m.Ticket) + len(extensions)

	return extensions, marshalSize, nil
}

func (m *MessageNewSessionTicket) marshalTo(out, extensions []byte) {
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
	copy(out[n:], extensions)
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
	m.SetExtensions(extensions)

	return nil
}
