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
	extensions         []extension.Value
}

const handshakeMessageClientHelloVariableWidthStart = 34

// Type returns the Handshake Type.
func (m MessageClientHello) Type() Type {
	return TypeClientHello
}

// Extensions returns the extensions.
func (m *MessageClientHello) Extensions() []extension.Value {
	return m.extensions
}

// SetExtensions replaces the extensions.
func (m *MessageClientHello) SetExtensions(extensions []extension.Value) {
	m.extensions = extensions
}

// MarshalSize returns the size needed for MarshalTo.
func (m *MessageClientHello) MarshalSize() int {
	cipherSuitesSize := 2 + 2*len(m.CipherSuiteIDs)
	compressionSize := 1 + len(m.CompressionMethods)

	return handshakeMessageClientHelloVariableWidthStart +
		1 +
		len(m.SessionID) +
		1 +
		len(m.Cookie) +
		cipherSuitesSize +
		compressionSize +
		extension.MarshalListSize(m.extensions)
}

// Marshal encodes the Handshake.
func (m *MessageClientHello) Marshal() ([]byte, error) {
	prepared, err := m.prepareMarshal()
	if err != nil {
		return nil, err
	}

	out := make([]byte, prepared.size)
	m.marshalTo(out, prepared.extensions)

	return out, nil
}

// MarshalTo encodes the Handshake into a pre-allocated buffer.
func (m *MessageClientHello) MarshalTo(out []byte) (int, error) {
	prepared, err := m.prepareMarshal()
	if err != nil {
		return prepared.size, err
	}
	if len(out) < prepared.size {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	m.marshalTo(out, prepared.extensions)

	return prepared.size, nil
}

type preparedClientHello struct {
	extensions extension.PreparedList
	size       int
}

func (m *MessageClientHello) prepareMarshal() (preparedClientHello, error) {
	if len(m.Cookie) > 255 {
		return preparedClientHello{}, dtlserrors.ErrCookieTooLong
	}
	if len(m.SessionID) > 255 {
		return preparedClientHello{}, dtlserrors.ErrSessionIDTooLong
	}
	if len(m.CompressionMethods) > 255 {
		return preparedClientHello{}, dtlserrors.ErrCompressionMethodsTooLong
	}

	extensions, err := extension.PrepareList(m.extensions)
	size := handshakeMessageClientHelloVariableWidthStart +
		1 + len(m.SessionID) +
		1 + len(m.Cookie) +
		2 + 2*len(m.CipherSuiteIDs) +
		1 + len(m.CompressionMethods) +
		extensions.MarshalSize()
	prepared := preparedClientHello{extensions: extensions, size: size}
	if size < 0 {
		return prepared, dtlserrors.ErrLengthMismatch
	}
	if err != nil {
		return prepared, err
	}

	return prepared, nil
}

func (m *MessageClientHello) marshalTo(out []byte, extensions extension.PreparedList) {
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

	binary.BigEndian.PutUint16(out[offset:], uint16(2*len(m.CipherSuiteIDs))) //nolint:gosec // G115: length is uint16.
	offset += 2
	for _, id := range m.CipherSuiteIDs {
		binary.BigEndian.PutUint16(out[offset:], id)
		offset += 2
	}

	out[offset] = byte(len(m.CompressionMethods)) //nolint:gosec // G115: validated to be <= 255 above.
	offset++
	for i := len(m.CompressionMethods); i > 0; i-- {
		out[offset] = byte(m.CompressionMethods[i-1].ID)
		offset++
	}

	_, _ = extensions.MarshalTo(out[offset:])
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
	m.SetExtensions(extensions)

	return nil
}
