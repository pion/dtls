// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// MessageServerHello is sent in response to a ClientHello
// message when it was able to find an acceptable set of algorithms.
// If it cannot find such a match, it will respond with a handshake
// failure alert.
//
// https://tools.ietf.org/html/rfc5246#section-7.4.1.3
type MessageServerHello struct {
	Version protocol.Version
	Random  Random

	SessionID []byte

	CipherSuiteID           *uint16
	CompressionMethod       *protocol.CompressionMethod
	Extensions              []extension.Extension
	marchalledExtensions    []byte
	marchalledExtensionsErr error
}

const messageServerHelloVariableWidthStart = 2 + RandomLength

// Type returns the Handshake Type.
func (m MessageServerHello) Type() Type {
	return TypeServerHello
}

func (m *MessageServerHello) cacheMarshalExtensions() error {
	if m.marchalledExtensions == nil && m.marchalledExtensionsErr == nil {
		m.marchalledExtensions, m.marchalledExtensionsErr = extension.Marshal(m.Extensions)
	}

	return m.marchalledExtensionsErr
}

// Size returns the size required by MarshalInto.
func (m *MessageServerHello) Size() int {
	err := m.cacheMarshalExtensions()
	if err != nil {
		return 0
	}

	total := 0
	total += len(m.marchalledExtensions)
	total += messageServerHelloVariableWidthStart + 1 + len(m.SessionID) + 2 + 1

	return total
}

// MarshalInto encodes the Handshake into a pre-allocated buffer.
func (m *MessageServerHello) MarshalInto(out []byte) error {
	err := m.cacheMarshalExtensions()
	if err != nil {
		return err
	}

	if len(out) < m.Size() {
		return errBufferTooSmall
	}

	offset := 0
	out[0] = m.Version.Major
	out[1] = m.Version.Minor
	offset += 2

	rand := m.Random.MarshalFixed()
	n := copy(out[offset:], rand[:])
	offset += n

	out[offset] = byte(len(m.SessionID)) //nolint:gosec // G115
	offset += 1
	n = copy(out[offset:], m.SessionID)
	offset += n

	binary.BigEndian.PutUint16(out[offset:], *m.CipherSuiteID)
	offset += 2

	out[offset] = byte(m.CompressionMethod.ID)
	offset += 1

	copy(out[offset:], m.marchalledExtensions)

	return nil
}

// Marshal encodes the Handshake.
func (m *MessageServerHello) Marshal() ([]byte, error) {
	switch {
	case m.CipherSuiteID == nil:
		return nil, errCipherSuiteUnset
	case m.CompressionMethod == nil:
		return nil, errCompressionMethodUnset
	case len(m.SessionID) > 255:
		return nil, errSessionIDTooLong
	}

	out := make([]byte, m.Size())
	err := m.MarshalInto(out)

	return out, err
}

// Unmarshal populates the message from encoded data.
func (m *MessageServerHello) Unmarshal(data []byte) error {
	if len(data) < 2+RandomLength {
		return errBufferTooSmall
	}

	m.Version.Major = data[0]
	m.Version.Minor = data[1]

	var random [RandomLength]byte
	copy(random[:], data[2:])
	m.Random.UnmarshalFixed(random)

	currOffset := messageServerHelloVariableWidthStart
	currOffset++
	if len(data) <= currOffset {
		return errBufferTooSmall
	}

	n := int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return errBufferTooSmall
	}
	m.SessionID = append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(m.SessionID)

	if len(data) < currOffset+2 {
		return errBufferTooSmall
	}
	m.CipherSuiteID = new(uint16)
	*m.CipherSuiteID = binary.BigEndian.Uint16(data[currOffset:])
	currOffset += 2

	if len(data) <= currOffset {
		return errBufferTooSmall
	}
	if compressionMethod, ok := protocol.CompressionMethods()[protocol.CompressionMethodID(data[currOffset])]; ok {
		m.CompressionMethod = compressionMethod
		currOffset++
	} else {
		return errInvalidCompressionMethod
	}

	if len(data) <= currOffset {
		m.Extensions = []extension.Extension{}

		return nil
	}

	extensions, err := extension.Unmarshal(data[currOffset:])
	if err != nil {
		return err
	}
	m.Extensions = extensions

	return nil
}
