// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
)

// MessageHelloVerifyRequest is as follows:
//
//	struct {
//	  ProtocolVersion server_version;
//	  opaque cookie<0..2^8-1>;
//	} HelloVerifyRequest;
//
//	The HelloVerifyRequest message type is hello_verify_request(3).
//
//	When the client sends its ClientHello message to the server, the server
//	MAY respond with a HelloVerifyRequest message.  This message contains
//	a stateless cookie generated using the technique of [PHOTURIS].  The
//	client MUST retransmit the ClientHello with the cookie added.
//
//	https://tools.ietf.org/html/rfc6347#section-4.2.1
type MessageHelloVerifyRequest struct {
	Version protocol.Version
	Cookie  []byte
}

// Type returns the Handshake Type.
func (m MessageHelloVerifyRequest) Type() Type {
	return TypeHelloVerifyRequest
}

// MarshalSize returns the size required for MarshalTo.
func (m *MessageHelloVerifyRequest) MarshalSize() int {
	return 3 + len(m.Cookie)
}

// Marshal encodes the Handshake.
func (m *MessageHelloVerifyRequest) Marshal() ([]byte, error) {
	if len(m.Cookie) > 255 {
		return nil, dtlserrors.ErrCookieTooLong
	}
	out := make([]byte, m.MarshalSize())
	_, err := m.MarshalTo(out)

	return out, err
}

// MarshalTo encodes the Handshake into a pre-allocated buffer.
func (m *MessageHelloVerifyRequest) MarshalTo(out []byte) (int, error) {
	if len(m.Cookie) > 255 {
		return 0, dtlserrors.ErrCookieTooLong
	}
	if len(out) < m.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}
	out[0] = m.Version.Major
	out[1] = m.Version.Minor
	out[2] = byte(len(m.Cookie)) //nolint:gosec // G115: cookie length is validated to be <= 255 above.
	copy(out[3:], m.Cookie)

	return m.MarshalSize(), nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageHelloVerifyRequest) Unmarshal(data []byte) error {
	if len(data) < 3 {
		return dtlserrors.ErrBufferTooSmall
	}
	m.Version.Major = data[0]
	m.Version.Minor = data[1]
	cookieLength := int(data[2])
	if len(data) < cookieLength+3 {
		return dtlserrors.ErrBufferTooSmall
	}
	m.Cookie = make([]byte, cookieLength)

	copy(m.Cookie, data[3:3+cookieLength])

	return nil
}
