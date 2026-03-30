// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"encoding/binary"

	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"golang.org/x/crypto/cryptobyte"
)

// CertificateEntry13 represents a single certificate entry in the DTLS 1.3 Certificate message.
// Each entry contains certificate data and optional per-certificate extensions.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
type CertificateEntry13 struct {
	// CertificateData contains the DER-encoded X.509 certificate.
	// Can be empty for certain contexts (e.g., RawPublicKey mode).
	CertificateData []byte

	// Extensions contains per-certificate extensions.
	// Examples: OCSP status, SignedCertificateTimestamp, etc.
	Extensions []extension.Extension
}

// MessageCertificate13 represents the Certificate handshake message for DTLS 1.3.
// This message is used to transport the certificate chain and associated extensions.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
type MessageCertificate13 struct {
	// CertificateRequestContext is an opaque value that binds this certificate
	// to a specific CertificateRequest (for client certificates) or is empty
	// for server certificates.
	CertificateRequestContext []byte

	// CertificateList contains the certificate chain with each entry having
	// optional per-certificate extensions.
	CertificateList         []CertificateEntry13
	marchalledExtensions    [][]byte
	marchalledExtensionsErr error
}

// Type returns the handshake message type.
func (m MessageCertificate13) Type() Type {
	return TypeCertificate
}

const (
	maxUint24                    = 0xffffff
	cert13ContextLengthFieldSize = 1
	cert13ContextMaxLength       = 255
	cert13CertLengthFieldSize    = 3
	cert13ExtLengthFieldSize     = 2
)

// Marshal encodes the MessageCertificate13 into its wire format.
//
// Wire format:
//
//	[1 byte]  certificate_request_context length
//	[0-255]   certificate_request_context data
//	[3 bytes] certificate_list length
//	For each certificate:
//	  [3 bytes]  cert_data length
//	  [variable] cert_data (DER certificate)
//	  [2 bytes]  extensions length (from extension.Marshal)
//	  [variable] extensions data
func (m *MessageCertificate13) Marshal() ([]byte, error) {
	// Validate certificate_request_context length
	if len(m.CertificateRequestContext) > cert13ContextMaxLength {
		return nil, errCertificateRequestContextTooLong
	}

	out := make([]byte, m.Size())
	err := m.MarshalInto(out)

	return out, err
}

func (m *MessageCertificate13) Size() int {
	return 1 + len(m.CertificateRequestContext) + cert13CertLengthFieldSize + m.certsSize()
}

func (m *MessageCertificate13) cacheMarshalExtensions() error {
	if m.marchalledExtensions == nil && m.marchalledExtensionsErr == nil {
		for _, entry := range m.CertificateList {
			for _, ext := range entry.Extensions {
				var c []byte
				c, m.marchalledExtensionsErr = ext.Marshal()
				if m.marchalledExtensionsErr != nil {
					return m.marchalledExtensionsErr
				}
				m.marchalledExtensions = append(m.marchalledExtensions, c)
			}
		}
	}
	return m.marchalledExtensionsErr
}

func (m *MessageCertificate13) certsSize() int {
	err := m.cacheMarshalExtensions()
	if err != nil {
		return 0
	}
	certificateListSize := 0
	for i, entry := range m.CertificateList {
		certificateListSize += cert13CertLengthFieldSize
		certificateListSize += len(entry.CertificateData)
		certificateListSize += len(m.marchalledExtensions[i])
	}

	return certificateListSize
}

// MarshalInto is same as Marshal but uses a pre-allocated buffer.
func (m *MessageCertificate13) MarshalInto(out []byte) error {
	// Validate certificate_request_context length
	if len(m.CertificateRequestContext) > cert13ContextMaxLength {
		return errCertificateRequestContextTooLong
	}

	if len(out) < m.Size() {
		return errBufferTooSmall
	}

	err := m.cacheMarshalExtensions()
	if err != nil {
		return err
	}

	// Check size of certificate_list is still within bounds
	if m.certsSize() > maxUint24 {
		return errCertificateListTooLong
	}

	// Start with certificate_request_context (1-byte length prefix)
	//nolint:gosec // G115: certificate_request_context length is validated to be <= 255 above.
	offset := 0
	out[0] = byte(len(m.CertificateRequestContext)) //nolint:gosec // G115
	offset += 1
	n := copy(out[offset:], m.CertificateRequestContext) //nolint:gosec // G115
	offset += n

	// Add certificate_list with 3-byte length prefix
	util.PutBigEndianUint24(out[offset:], uint32(m.certsSize())) //nolint:gosec // G115
	offset += 3

	// Build certificate_list
	for _, entry := range m.CertificateList {
		// Add cert_data as a 3-byte length prefix
		certDataLen := len(entry.CertificateData)
		if certDataLen == 0 || certDataLen > maxUint24 {
			return errInvalidCertificateEntry
		}
		util.PutBigEndianUint24(out[offset:], uint32(certDataLen)) //nolint:gosec // G115
		offset += 3
		n = copy(out[offset:], entry.CertificateData)
		offset += n

		// Marshal extensions (includes a 2-byte length prefix)
		extensionsData, err := extension.Marshal(entry.Extensions)
		if err != nil {
			return err
		}
		n = copy(out[offset:], extensionsData)
		offset += n
	}

	return nil
}

// parseCertificate13Entry parses a single certificate entry from the cryptobyte string.
func parseCertificate13Entry(str *cryptobyte.String) (*CertificateEntry13, error) {
	// Read cert_data with 3-byte length prefix
	var certData cryptobyte.String
	if !str.ReadUint24LengthPrefixed(&certData) {
		return nil, errInvalidCertificateEntry
	}

	// Validate cert_data length is in valid range <1..2^24-1>
	if len(certData) == 0 {
		return nil, errInvalidCertificateEntry
	}

	// Copy cert_data to avoid aliasing issues
	certDataBytes := make([]byte, len(certData))
	copy(certDataBytes, certData)

	// Validate extensions length (2-byte length prefix + up to 2^16-1 bytes of data)
	if len(*str) < cert13ExtLengthFieldSize {
		return nil, errInvalidCertificateEntry
	}

	// Read extensions length to validate we have enough data
	extensionsLen := binary.BigEndian.Uint16([]byte(*str)[:cert13ExtLengthFieldSize])
	if len(*str) < cert13ExtLengthFieldSize+int(extensionsLen) {
		return nil, errInvalidCertificateEntry
	}

	// Unmarshal extensions data
	extensionsData := []byte(*str)[:cert13ExtLengthFieldSize+int(extensionsLen)]
	extensions, err := extension.Unmarshal(extensionsData)
	if err != nil {
		return nil, err
	}

	// Advance the cryptobyte.String's position
	if !str.Skip(cert13ExtLengthFieldSize + int(extensionsLen)) {
		return nil, errInvalidCertificateEntry
	}

	return &CertificateEntry13{
		CertificateData: certDataBytes,
		Extensions:      extensions,
	}, nil
}

// Unmarshal decodes the MessageCertificate13 from its wire format.
func (m *MessageCertificate13) Unmarshal(data []byte) error {
	// Validate minimum data length
	if len(data) < cert13ContextLengthFieldSize+cert13CertLengthFieldSize {
		return errBufferTooSmall
	}

	str := cryptobyte.String(data)

	// Read certificate_request_context with 1-byte length prefix
	var contextData cryptobyte.String
	if !str.ReadUint8LengthPrefixed(&contextData) {
		return errInvalidCertificateRequestContext
	}
	m.CertificateRequestContext = make([]byte, len(contextData))
	copy(m.CertificateRequestContext, contextData)

	// Read certificate_list with 3-byte length prefix
	var certificateListData cryptobyte.String
	if !str.ReadUint24LengthPrefixed(&certificateListData) {
		return errInvalidCertificateEntry
	}

	// Ensure no trailing data
	if len(str) != 0 {
		return errLengthMismatch
	}

	// Parse certificate_list
	m.CertificateList = []CertificateEntry13{}
	for len(certificateListData) > 0 {
		entry, err := parseCertificate13Entry(&certificateListData)
		if err != nil {
			return err
		}
		m.CertificateList = append(m.CertificateList, *entry)
	}

	return nil
}
