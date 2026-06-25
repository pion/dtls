// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package handshake provides the DTLS wire protocol for handshakes
package handshake

import (
	"github.com/pion/dtls/v3/internal/ciphersuite/types"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/protocol"
)

// Type is the unique identifier for each handshake message
// https://tools.ietf.org/html/rfc5246#section-7.4
type Type uint8

// Types of DTLS Handshake messages we know about.
const (
	TypeHelloRequest       Type = 0
	TypeClientHello        Type = 1
	TypeServerHello        Type = 2
	TypeHelloVerifyRequest Type = 3
	TypeCertificate        Type = 11
	TypeServerKeyExchange  Type = 12
	TypeCertificateRequest Type = 13
	TypeServerHelloDone    Type = 14
	TypeCertificateVerify  Type = 15
	TypeClientKeyExchange  Type = 16
	TypeFinished           Type = 20

	// TypeMessageHash is a synthetic TLS 1.3 transcript-only handshake type.
	TypeMessageHash Type = 254
)

// HelloRetryRequestRandom is set as the Random value of a ServerHello
// to signal that the message is actually a HelloRetryRequest.
// See RFC 8446 Section 4.1.3.
func HelloRetryRequestRandom() []byte {
	return []byte{
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
		0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
	}
}

// String returns the string representation of this type.
func (t Type) String() string { //nolint:cyclop
	switch t {
	case TypeHelloRequest:
		return "HelloRequest"
	case TypeClientHello:
		return "ClientHello"
	case TypeServerHello:
		return "ServerHello"
	case TypeHelloVerifyRequest:
		return "HelloVerifyRequest"
	case TypeCertificate:
		return "TypeCertificate"
	case TypeServerKeyExchange:
		return "ServerKeyExchange"
	case TypeCertificateRequest:
		return "CertificateRequest"
	case TypeServerHelloDone:
		return "ServerHelloDone"
	case TypeCertificateVerify:
		return "CertificateVerify"
	case TypeClientKeyExchange:
		return "ClientKeyExchange"
	case TypeFinished:
		return "Finished"
	case TypeMessageHash:
		return "MessageHash"
	}

	return ""
}

// Message is the body of a Handshake datagram.
type Message interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
	Type() Type
}

// Handshake protocol is responsible for selecting a cipher spec and
// generating a master secret, which together comprise the primary
// cryptographic parameters associated with a secure session.  The
// handshake protocol can also optionally authenticate parties who have
// certificates signed by a trusted certificate authority.
// https://tools.ietf.org/html/rfc5246#section-7.3
type Handshake struct {
	Header  Header
	Message Message

	KeyExchangeAlgorithm types.KeyExchangeAlgorithm
}

// ContentType returns what kind of content this message is carying.
func (h Handshake) ContentType() protocol.ContentType {
	return protocol.ContentTypeHandshake
}

// Marshal encodes a handshake into a binary message.
func (h *Handshake) Marshal() ([]byte, error) {
	if h.Message == nil {
		return nil, dtlserrors.ErrHandshakeMessageUnset
	} else if h.Header.FragmentOffset != 0 {
		return nil, dtlserrors.ErrUnableToMarshalFragmented
	}

	msg, err := h.Message.Marshal()
	if err != nil {
		return nil, err
	}

	h.Header.Length = uint32(len(msg)) //nolint:gosec // G115
	h.Header.FragmentLength = h.Header.Length
	h.Header.Type = h.Message.Type()
	header, err := h.Header.Marshal()
	if err != nil {
		return nil, err
	}

	return append(header, msg...), nil
}

// Unmarshal decodes a handshake from a binary message.
func (h *Handshake) Unmarshal(data []byte) error { //nolint:cyclop
	if err := h.Header.Unmarshal(data); err != nil {
		return err
	}

	reportedLen := util.BigEndianUint24(data[1:])
	if uint32(len(data)-HeaderLength) != reportedLen { //nolint:gosec // G115
		return dtlserrors.ErrLengthMismatch
	} else if reportedLen != h.Header.FragmentLength {
		return dtlserrors.ErrLengthMismatch
	}

	switch Type(data[0]) {
	case TypeHelloRequest:
		return dtlserrors.ErrNotImplemented
	case TypeClientHello:
		h.Message = &MessageClientHello{}
	case TypeHelloVerifyRequest:
		h.Message = &MessageHelloVerifyRequest{}
	case TypeServerHello:
		h.Message = &MessageServerHello{}
	case TypeCertificate:
		h.Message = &MessageCertificate{}
	case TypeServerKeyExchange:
		h.Message = &MessageServerKeyExchange{KeyExchangeAlgorithm: h.KeyExchangeAlgorithm}
	case TypeCertificateRequest:
		h.Message = &MessageCertificateRequest{}
	case TypeServerHelloDone:
		h.Message = &MessageServerHelloDone{}
	case TypeClientKeyExchange:
		h.Message = &MessageClientKeyExchange{KeyExchangeAlgorithm: h.KeyExchangeAlgorithm}
	case TypeFinished:
		h.Message = &MessageFinished{}
	case TypeCertificateVerify:
		h.Message = &MessageCertificateVerify{}
	default:
		return dtlserrors.ErrNotImplemented
	}

	return h.Message.Unmarshal(data[HeaderLength:])
}
