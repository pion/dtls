// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"
	"encoding/binary"
	"fmt"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
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
	Extensions              []extension.Value
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
		m.marchalledExtensions, m.marchalledExtensionsErr = extension.MarshalList(m.Extensions)
	}

	return m.marchalledExtensionsErr
}

// MarshalSize returns the size required by MarshalTo.
func (m *MessageServerHello) MarshalSize() int {
	err := m.cacheMarshalExtensions()
	if err != nil {
		return 0
	}

	total := 0
	total += len(m.marchalledExtensions)
	total += messageServerHelloVariableWidthStart + 1 + len(m.SessionID) + 2 + 1

	return total
}

// Marshal encodes the Handshake.
func (m *MessageServerHello) Marshal() ([]byte, error) {
	switch {
	case m.CipherSuiteID == nil:
		return nil, dtlserrors.ErrCipherSuiteUnset
	case m.CompressionMethod == nil:
		return nil, dtlserrors.ErrCompressionMethodUnset
	case len(m.SessionID) > 255:
		return nil, dtlserrors.ErrSessionIDTooLong
	}

	out := make([]byte, m.MarshalSize())
	_, err := m.MarshalTo(out)

	return out, err
}

// MarshalTo encodes the Handshake into a pre-allocated buffer.
func (m *MessageServerHello) MarshalTo(out []byte) (int, error) {
	if len(out) < m.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	switch {
	case m.CipherSuiteID == nil:
		return 0, dtlserrors.ErrCipherSuiteUnset
	case m.CompressionMethod == nil:
		return 0, dtlserrors.ErrCompressionMethodUnset
	case len(m.SessionID) > 255:
		return 0, dtlserrors.ErrSessionIDTooLong
	}

	err := m.cacheMarshalExtensions()
	if err != nil {
		return 0, err
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

	return m.MarshalSize(), nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageServerHello) Unmarshal(data []byte) error { //nolint:cyclop
	if len(data) < 2+RandomLength {
		return dtlserrors.ErrBufferTooSmall
	}

	m.Version.Major = data[0]
	m.Version.Minor = data[1]

	var random [RandomLength]byte
	copy(random[:], data[2:])
	m.Random.UnmarshalFixed(random)

	currOffset := messageServerHelloVariableWidthStart
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

	if len(data) < currOffset+2 {
		return dtlserrors.ErrBufferTooSmall
	}
	m.CipherSuiteID = new(uint16)
	*m.CipherSuiteID = binary.BigEndian.Uint16(data[currOffset:])
	currOffset += 2

	if len(data) <= currOffset {
		return dtlserrors.ErrBufferTooSmall
	}
	if compressionMethod, ok := protocol.CompressionMethods()[protocol.CompressionMethodID(data[currOffset])]; ok {
		m.CompressionMethod = compressionMethod
		currOffset++
	} else {
		return dtlserrors.ErrInvalidCompressionMethod
	}

	if len(data) <= currOffset {
		context := serverHelloExtensionContext(m.Random, nil)
		extensions, err := decodeRawExtensions(nil, context)
		if err != nil {
			return err
		}
		m.Extensions = extensions

		return nil
	}

	rawExtensions, err := extension.ParseList(data[currOffset:])
	if err != nil {
		context := extensionContextServerHello12
		randomBytes := m.Random.MarshalFixed()
		if bytes.Equal(randomBytes[:], HelloRetryRequestRandom()) {
			context = extensionContextHelloRetryRequest
		}

		return fmt.Errorf(
			"extensions in %s: %w: %w",
			context,
			err,
			&alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
		)
	}
	context := serverHelloExtensionContext(m.Random, rawExtensions)
	extensions, err := decodeRawExtensions(rawExtensions, context)
	if err != nil {
		return err
	}
	m.Extensions = extensions

	return nil
}
