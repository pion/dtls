// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package handshakewire provides shared handshake types and extension decoding.
package handshakewire

// Type is the unique identifier for each handshake message
// https://tools.ietf.org/html/rfc5246#section-7.4
type Type uint8

// Types of DTLS Handshake messages we know about.
const (
	TypeHelloRequest        Type = 0
	TypeClientHello         Type = 1
	TypeServerHello         Type = 2
	TypeHelloVerifyRequest  Type = 3
	TypeNewSessionTicket    Type = 4
	TypeEncryptedExtensions Type = 8
	TypeRequestConnectionID Type = 9
	TypeNewConnectionID     Type = 10
	TypeCertificate         Type = 11
	TypeServerKeyExchange   Type = 12
	TypeCertificateRequest  Type = 13
	TypeServerHelloDone     Type = 14
	TypeCertificateVerify   Type = 15
	TypeClientKeyExchange   Type = 16
	TypeFinished            Type = 20
	TypeKeyUpdate           Type = 24

	// TypeMessageHash is a synthetic TLS 1.3 transcript-only handshake type.
	TypeMessageHash Type = 254
)

// String returns the string representation of this type.
func (t Type) String() string {
	switch t {
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
	case TypeCertificateVerify:
		return "CertificateVerify"
	case TypeFinished:
		return "Finished"
	default:
		return t.legacyName()
	}
}

func (t Type) legacyName() string {
	switch t {
	case TypeHelloRequest:
		return "HelloRequest"
	case TypeServerHelloDone:
		return "ServerHelloDone"
	case TypeClientKeyExchange:
		return "ClientKeyExchange"
	default:
		return t.dtls13Name()
	}
}

func (t Type) dtls13Name() string {
	switch t {
	case TypeNewSessionTicket:
		return "NewSessionTicket"
	case TypeEncryptedExtensions:
		return "EncryptedExtensions"
	case TypeRequestConnectionID:
		return "RequestConnectionID"
	case TypeNewConnectionID:
		return "NewConnectionID"
	case TypeKeyUpdate:
		return "KeyUpdate"
	case TypeMessageHash:
		return "MessageHash"
	default:
		return ""
	}
}
