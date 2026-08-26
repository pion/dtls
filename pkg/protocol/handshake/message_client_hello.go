// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

/*
MessageClientHello is for when a client first connects to a server it is
required to send the client hello as its first message.  The client can also send a
client hello in response to a hello request or on its own
initiative in order to renegotiate the security parameters in an
existing connection.
*/
type MessageClientHello struct {
	Version protocol.Version
	Random  Random
	Cookie  []byte

	SessionID []byte

	CipherSuiteIDs     []uint16
	CompressionMethods []*protocol.CompressionMethod
	CachedExtensions   extension.CachedList
}

const handshakeMessageClientHelloVariableWidthStart = 34

// Type returns the Handshake Type.
func (m MessageClientHello) Type() Type {
	return TypeClientHello
}

// Extensions returns the extensions.
func (m *MessageClientHello) Extensions() []extension.Value {
	return m.CachedExtensions.Values
}

// MarshalSize returns the size needed for MarshalTo.
func (m *MessageClientHello) MarshalSize() int {
	encodedCipherSuiteIDs := encodeCipherSuiteIDs(m.CipherSuiteIDs)
	encodedCompressionMethods := protocol.EncodeCompressionMethods(m.CompressionMethods)

	return handshakeMessageClientHelloVariableWidthStart +
		1 +
		len(m.SessionID) +
		1 +
		len(m.Cookie) +
		len(encodedCipherSuiteIDs) +
		len(encodedCompressionMethods) +
		m.CachedExtensions.MarshalSize()
}

// Marshal encodes the Handshake.
func (m *MessageClientHello) Marshal() ([]byte, error) {
	out := make([]byte, m.MarshalSize())
	_, err := m.MarshalTo(out)

	return out, err
}

// MarshalTo encodes the Handshake into a pre-allocated buffer.
func (m *MessageClientHello) MarshalTo(out []byte) (int, error) {
	if len(m.Cookie) > 255 {
		return 0, dtlserrors.ErrCookieTooLong
	}
	if len(m.SessionID) > 255 {
		return 0, dtlserrors.ErrSessionIDTooLong
	}
	if len(m.CompressionMethods) > 255 {
		return 0, dtlserrors.ErrCompressionMethodsTooLong
	}

	if len(out) < m.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	encodedCipherSuiteIDs := encodeCipherSuiteIDs(m.CipherSuiteIDs)
	encodedCompressionMethods := protocol.EncodeCompressionMethods(m.CompressionMethods)

	offset := 0
	out[0] = m.Version.Major
	out[1] = m.Version.Minor
	offset += 2

	rand := m.Random.MarshalFixed()
	n := copy(out[offset:], rand[:])
	offset += n
	out[offset] = byte(len(m.SessionID)) //nolint:gosec // G115: session ID length is validated to be <= 255 above.
	offset += 1

	n = copy(out[offset:], m.SessionID)
	offset += n

	out[offset] = byte(len(m.Cookie)) //nolint:gosec // G115: cookie length is validated to be <= 255 above.
	offset += 1

	n = copy(out[offset:], m.Cookie)
	offset += n

	n = copy(out[offset:], encodedCipherSuiteIDs)
	offset += n

	n = copy(out[offset:], encodedCompressionMethods)
	offset += n

	_, err := m.CachedExtensions.MarshalTo(out[offset:])

	return m.MarshalSize(), err
}

// Unmarshal populates the message from encoded data.
func (m *MessageClientHello) Unmarshal(data []byte) error { //nolint:cyclop
	if len(data) < 2+RandomLength {
		return dtlserrors.ErrBufferTooSmall
	}

	m.Version.Major = data[0]
	m.Version.Minor = data[1]

	var random [RandomLength]byte
	copy(random[:], data[2:])
	m.Random.UnmarshalFixed(random)

	// rest of packet has variable width sections
	currOffset := handshakeMessageClientHelloVariableWidthStart

	currOffset++
	if len(data) <= currOffset {
		return dtlserrors.ErrBufferTooSmall
	}
	n := int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return dtlserrors.ErrBufferTooSmall
	}
	m.SessionID = bytes.Clone(data[currOffset : currOffset+n])
	currOffset += len(m.SessionID)

	currOffset++
	if len(data) <= currOffset {
		return dtlserrors.ErrBufferTooSmall
	}
	n = int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return dtlserrors.ErrBufferTooSmall
	}
	m.Cookie = bytes.Clone(data[currOffset : currOffset+n])
	currOffset += len(m.Cookie)

	// Cipher Suites
	if len(data) < currOffset {
		return dtlserrors.ErrBufferTooSmall
	}
	cipherSuiteIDs, err := decodeCipherSuiteIDs(data[currOffset:])
	if err != nil {
		return err
	}
	m.CipherSuiteIDs = cipherSuiteIDs
	if len(data) < currOffset+2 {
		return dtlserrors.ErrBufferTooSmall
	}
	currOffset += int(binary.BigEndian.Uint16(data[currOffset:])) + 2

	// Compression Methods
	if len(data) < currOffset {
		return dtlserrors.ErrBufferTooSmall
	}
	compressionMethods, err := protocol.DecodeCompressionMethods(data[currOffset:])
	if err != nil {
		return err
	}
	m.CompressionMethods = compressionMethods
	if len(data) < currOffset {
		return dtlserrors.ErrBufferTooSmall
	}
	currOffset += int(data[currOffset]) + 1

	// Extensions
	extensions, err := decodeExtensionList(data[currOffset:], extensionContextClientHello)
	if err != nil {
		return err
	}
	m.CachedExtensions = extension.CachedList{
		Values: extensions,
	}

	return nil
}
