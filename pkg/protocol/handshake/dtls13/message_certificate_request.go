// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"bytes"
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/handshakewire"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	"golang.org/x/crypto/cryptobyte"
)

// MessageCertificateRequest represents the CertificateRequest handshake message for DTLS 1.3.
// This message is used by the server to request a certificate from the client.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
type MessageCertificateRequest struct {
	// CertificateRequestContext is an opaque value that the server creates
	// to bind the client's certificate to the handshake context.
	CertificateRequestContext []byte

	// Extensions contains the list of extensions.
	// The signature_algorithms extension is REQUIRED per RFC 8446.
	Extensions []extension.Value
}

// Type returns the handshake message type.
func (m MessageCertificateRequest) Type() handshakewire.Type {
	return handshakewire.TypeCertificateRequest
}

const (
	maxUint16                 = 0xffff
	certReq13ContextMaxLength = 255
	certReq13MinLength        = 3
)

// Marshal encodes the MessageCertificateRequest into its wire format.
//
// Wire format:
//
//	[1 byte]  certificate_request_context length
//	[0-255]   certificate_request_context data
//	[2 bytes] extensions length (from extension.MarshalList)
//	[variable] extensions data
func (m *MessageCertificateRequest) Marshal() ([]byte, error) {
	extensions, marshalSize, err := m.prepareMarshal()
	if err != nil {
		return nil, err
	}

	out := make([]byte, marshalSize)
	m.marshalTo(out, extensions)

	return out, nil
}

// MarshalSize returns the size needed for MarshalTo.
func (m *MessageCertificateRequest) MarshalSize() int {
	return 1 + len(m.CertificateRequestContext) + extension.MarshalListSize(m.Extensions)
}

// MarshalTo encodes like Marshal but in a pre-allocate buffer.
func (m *MessageCertificateRequest) MarshalTo(out []byte) (int, error) {
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

func (m *MessageCertificateRequest) prepareMarshal() ([]byte, int, error) {
	// Validate certificate_request_context length
	if len(m.CertificateRequestContext) > certReq13ContextMaxLength {
		return nil, 0, dtlserrors.ErrCertificateRequestContextTooLong
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
		return nil, 0, dtlserrors.ErrMissingSignatureAlgorithmsExtension
	}

	extensions, err := extension.MarshalList(m.Extensions)
	if err != nil {
		return nil, 0, err
	}
	if len(extensions) < 2 || len(extensions) > maxUint16 {
		return nil, 0, dtlserrors.ErrInvalidExtensionsLength
	}

	marshalSize := 1 + len(m.CertificateRequestContext) + len(extensions)

	return extensions, marshalSize, nil
}

func (m *MessageCertificateRequest) marshalTo(out, extensions []byte) {
	n := 0
	out[0] = byte(len(m.CertificateRequestContext)) //nolint:gosec // G115
	n += 1
	n += copy(out[1:], m.CertificateRequestContext)
	copy(out[n:], extensions)
}

// Unmarshal decodes the MessageCertificateRequest from its wire format.
func (m *MessageCertificateRequest) Unmarshal(data []byte) error {
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

	extensions, err := handshakewire.DecodeExtensionList([]byte(str), handshakewire.ContextCertificateRequest)
	if err != nil {
		return err
	}

	m.Extensions = extensions

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
