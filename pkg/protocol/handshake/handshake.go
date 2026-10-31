// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package handshake provides the DTLS wire protocol for handshakes
package handshake

import (
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/handshakewire"
	"github.com/pion/dtls/v4/internal/util"
	"github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/protocol"
	handshake12 "github.com/pion/dtls/v4/pkg/protocol/handshake/dtls12"
	handshake13 "github.com/pion/dtls/v4/pkg/protocol/handshake/dtls13"
)

// Type is the unique identifier for each handshake message.
// https://tools.ietf.org/html/rfc5246#section-7.4
type Type = handshakewire.Type

// Types of DTLS Handshake messages we know about.
const (
	TypeHelloRequest        = handshakewire.TypeHelloRequest
	TypeClientHello         = handshakewire.TypeClientHello
	TypeServerHello         = handshakewire.TypeServerHello
	TypeHelloVerifyRequest  = handshakewire.TypeHelloVerifyRequest
	TypeNewSessionTicket    = handshakewire.TypeNewSessionTicket
	TypeEncryptedExtensions = handshakewire.TypeEncryptedExtensions
	TypeRequestConnectionID = handshakewire.TypeRequestConnectionID
	TypeNewConnectionID     = handshakewire.TypeNewConnectionID
	TypeCertificate         = handshakewire.TypeCertificate
	TypeServerKeyExchange   = handshakewire.TypeServerKeyExchange
	TypeCertificateRequest  = handshakewire.TypeCertificateRequest
	TypeServerHelloDone     = handshakewire.TypeServerHelloDone
	TypeCertificateVerify   = handshakewire.TypeCertificateVerify
	TypeClientKeyExchange   = handshakewire.TypeClientKeyExchange
	TypeFinished            = handshakewire.TypeFinished
	TypeKeyUpdate           = handshakewire.TypeKeyUpdate
	// TypeMessageHash is a synthetic TLS 1.3 transcript-only handshake type.
	TypeMessageHash = handshakewire.TypeMessageHash
)

// HelloRetryRequestRandom is set as the Random value of a ServerHello
// to signal that the message is actually a HelloRetryRequest.
// See RFC 8446 Section 4.1.3.
func HelloRetryRequestRandom() []byte {
	return []byte{0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C}
}

// Message is the body of a Handshake datagram.
type Message interface {
	Marshal() ([]byte, error)
	MarshalTo([]byte) (int, error)
	MarshalSize() int
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

	KeyExchangeAlgorithm ciphersuite.KeyExchangeAlgorithm

	// Version selects version-dependent message formats during Unmarshal.
	// Zero uses DTLS 1.3.
	Version protocol.Version
}

// ContentType returns what kind of content this message is carying.
func (h Handshake) ContentType() protocol.ContentType {
	return protocol.ContentTypeHandshake
}

// MarshalSize returns the minimal buffer size required for MarshalTo.
func (h *Handshake) MarshalSize() int {
	if h.Message == nil {
		return 0
	}

	return HeaderLength + h.Message.MarshalSize()
}

// Marshal encodes a handshake into a binary message.
func (h *Handshake) Marshal() ([]byte, error) {
	if h.Message == nil {
		return nil, dtlserrors.ErrHandshakeMessageUnset
	} else if h.Header.FragmentOffset != 0 {
		return nil, dtlserrors.ErrUnableToMarshalFragmented
	}

	out := make([]byte, HeaderLength+h.Message.MarshalSize())
	n, err := h.Message.MarshalTo(out[HeaderLength:])
	if err != nil {
		return nil, err
	}

	h.Header.Length = uint32(n) //nolint:gosec // handshake messages are bounded to uint24 on the wire.
	h.Header.FragmentLength = h.Header.Length
	h.Header.Type = h.Message.Type()
	if _, err = h.Header.MarshalTo(out); err != nil {
		return nil, err
	}

	return out, nil
}

// MarshalTo encodes a handshake into a binary message into a pre-allocated buffer.
func (h *Handshake) MarshalTo(out []byte) (int, error) {
	if h.Message == nil {
		return 0, dtlserrors.ErrHandshakeMessageUnset
	} else if h.Header.FragmentOffset != 0 {
		return 0, dtlserrors.ErrUnableToMarshalFragmented
	}

	if len(out) < h.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	h.Header.Length = uint32(h.Message.MarshalSize()) //nolint:gosec // G115
	h.Header.FragmentLength = h.Header.Length
	h.Header.Type = h.Message.Type()
	n, err := h.Header.MarshalTo(out)
	if err != nil {
		return n, err
	}

	nn, err := h.Message.MarshalTo(out[n:])

	return n + nn, err
}

// Unmarshal decodes a handshake from a binary message.
func (h *Handshake) Unmarshal(data []byte) error {
	if err := h.Header.Unmarshal(data); err != nil {
		return err
	}

	reportedLen := util.BigEndianUint24(data[1:])
	if uint32(len(data)-HeaderLength) != reportedLen { //nolint:gosec // G115
		return dtlserrors.ErrLengthMismatch
	} else if reportedLen != h.Header.FragmentLength {
		return dtlserrors.ErrLengthMismatch
	}

	message, err := newHandshakeMessage(Type(data[0]), h.KeyExchangeAlgorithm, h.Version)
	if err != nil {
		return err
	}
	h.Message = message

	return h.Message.Unmarshal(data[HeaderLength:])
}

func newHandshakeMessage(messageType Type, keyExchangeAlgorithm ciphersuite.KeyExchangeAlgorithm, version protocol.Version) (Message, error) {
	if version != 0 && version != protocol.Version1_2 && version != protocol.Version1_3 {
		return nil, dtlserrors.ErrUnsupportedProtocolVersion
	}

	switch messageType {
	case TypeCertificate:
		if version == protocol.Version1_2 {
			return &handshake12.MessageCertificate{}, nil
		}

		return &handshake13.MessageCertificate{}, nil
	case TypeCertificateRequest:
		if version == protocol.Version1_2 {
			return &handshake12.MessageCertificateRequest{}, nil
		}

		return &handshake13.MessageCertificateRequest{}, nil
	default:
		return newCommonHandshakeMessage(messageType, keyExchangeAlgorithm)
	}
}

func newCommonHandshakeMessage(messageType Type, keyExchangeAlgorithm ciphersuite.KeyExchangeAlgorithm) (Message, error) {
	switch messageType {
	case TypeClientHello:
		return &MessageClientHello{}, nil
	case TypeHelloVerifyRequest:
		return &MessageHelloVerifyRequest{}, nil
	case TypeServerHello:
		return &MessageServerHello{}, nil
	case TypeServerKeyExchange:
		return &MessageServerKeyExchange{KeyExchangeAlgorithm: keyExchangeAlgorithm}, nil
	case TypeServerHelloDone:
		return &MessageServerHelloDone{}, nil
	case TypeClientKeyExchange:
		return &MessageClientKeyExchange{KeyExchangeAlgorithm: keyExchangeAlgorithm}, nil
	default:
		return newAdditionalHandshakeMessage(messageType)
	}
}

func newAdditionalHandshakeMessage(messageType Type) (Message, error) {
	switch messageType {
	case TypeFinished:
		return &MessageFinished{}, nil
	case TypeNewSessionTicket:
		return &MessageNewSessionTicket{}, nil
	case TypeEncryptedExtensions:
		return &MessageEncryptedExtensions{}, nil
	case TypeRequestConnectionID:
		return &MessageRequestConnectionID{}, nil
	case TypeNewConnectionID:
		return &MessageNewConnectionID{}, nil
	case TypeCertificateVerify:
		return &MessageCertificateVerify{}, nil
	case TypeKeyUpdate:
		return &MessageKeyUpdate{}, nil
	default:
		return nil, dtlserrors.ErrUnsupportedHandshakeType
	}
}
