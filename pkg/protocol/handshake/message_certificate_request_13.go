// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"golang.org/x/crypto/cryptobyte"
)

// MessageCertificateRequest13 represents the CertificateRequest handshake message for DTLS 1.3.
// This message is used by the server to request a certificate from the client.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
type MessageCertificateRequest13 struct {
	// CertificateRequestContext is an opaque value that the server creates
	// to bind the client's certificate to the handshake context.
	CertificateRequestContext []byte

	// Extensions contains the list of extensions.
	// The signature_algorithms extension is REQUIRED per RFC 8446.
	Extensions []extension.Value

	// Cache the marshal result
	marshalCache    []byte
	marshalCacheErr error
}

// Type returns the handshake message type.
func (m MessageCertificateRequest13) Type() Type {
	return TypeCertificateRequest
}

const (
	maxUint16                 = 0xffff
	certReq13ContextMaxLength = 255
	certReq13MinLength        = 3
)

// Marshal encodes the MessageCertificateRequest13 into its wire format.
//
// Wire format:
//
//	[1 byte]  certificate_request_context length
//	[0-255]   certificate_request_context data
//	[2 bytes] extensions length (from extension.MarshalList)
//	[variable] extensions data
func (m *MessageCertificateRequest13) Marshal() ([]byte, error) {
	out := make([]byte, m.MarshalSize())
	_, err := m.MarshalTo(out)

	return out, err
}

// MarshalSize returns the size needed for MarshalTo.
func (m *MessageCertificateRequest13) MarshalSize() int {
	cache, err := m.innerMarshal()
	if err != nil {
		return 0
	}

	return len(cache)
}

func (m *MessageCertificateRequest13) innerMarshal() ([]byte, error) {
	if m.marshalCache == nil && m.marshalCacheErr == nil {
		var builder cryptobyte.Builder

		// Add certificate_request_context (1-byte length prefix)
		builder.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.CertificateRequestContext)
		})

		// Marshal extensions (includes 2-byte length prefix, like in TLS 1.2)
		extensionsData, err := extension.MarshalList(m.Extensions)
		if err != nil {
			m.marshalCacheErr = err

			return nil, err
		}
		// Validate extensions length is in valid range <2..2^16-1>
		if len(extensionsData) < 2 || len(extensionsData) > maxUint16 {
			m.marshalCacheErr = err

			return nil, dtlserrors.ErrInvalidExtensionsLength
		}
		builder.AddBytes(extensionsData)

		m.marshalCache, m.marshalCacheErr = builder.Bytes()
	}

	return m.marshalCache, m.marshalCacheErr
}

// MarshalTo encodes like Marshal but in a pre-allocate buffer.
func (m *MessageCertificateRequest13) MarshalTo(out []byte) (int, error) {
	// Validate certificate_request_context length
	if len(m.CertificateRequestContext) > certReq13ContextMaxLength {
		return 0, dtlserrors.ErrCertificateRequestContextTooLong
	}

	// Validate that signature_algorithms extension is present (required by RFC 8446)
	hasSignatureAlgorithms := false
	for _, ext := range m.Extensions {
		if ext.ExtensionType() == extension.TypeSignatureAlgorithms {
			hasSignatureAlgorithms = true

			break
		}
	}
	if !hasSignatureAlgorithms {
		return 0, dtlserrors.ErrMissingSignatureAlgorithmsExtension
	}

	if len(out) < m.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	cache, err := m.innerMarshal()
	if err != nil {
		return 0, err
	}

	copy(out, cache)

	return m.MarshalSize(), nil
}

// Unmarshal decodes the MessageCertificateRequest13 from its wire format.
func (m *MessageCertificateRequest13) Unmarshal(data []byte) error {
	// Validate minimum data length
	if len(data) < certReq13MinLength {
		return dtlserrors.ErrBufferTooSmall
	}

	str := cryptobyte.String(data)

	// Read certificate_request_context
	var contextData cryptobyte.String
	if !str.ReadUint8LengthPrefixed(&contextData) {
		return dtlserrors.ErrInvalidCertificateRequestContext
	}
	m.CertificateRequestContext = bytes.Clone(contextData)

	// Read extensions length (2 bytes)
	if len(str) < 2 {
		return dtlserrors.ErrInvalidExtensionsLength
	}
	extensionsLen := binary.BigEndian.Uint16(str[:2])

	// Validate we have exactly extensionsLen bytes remaining after the length field
	if len(str[2:]) != int(extensionsLen) {
		return dtlserrors.ErrLengthMismatch
	}

	var err error
	m.Extensions, err = decodeExtensionList([]byte(str), extensionContextCertificateRequest)
	if err != nil {
		return err
	}

	// Validate that signature_algorithms extension is present (required by RFC 8446)
	hasSignatureAlgorithms := false
	for _, ext := range m.Extensions {
		if ext.ExtensionType() == extension.TypeSignatureAlgorithms {
			hasSignatureAlgorithms = true

			break
		}
	}
	if !hasSignatureAlgorithms {
		return dtlserrors.ErrMissingSignatureAlgorithmsExtension
	}

	return nil
}
