// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
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

	// extensions contains per-certificate extensions.
	// Examples: OCSP status, SignedCertificateTimestamp, etc.
	extensions []extension.Value
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
	CertificateList []CertificateEntry13
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

// Extensions returns extensions.
func (m CertificateEntry13) Extensions() []extension.Value {
	return m.extensions
}

// SetExtensions replaces the per-certificate extensions.
func (m *CertificateEntry13) SetExtensions(extensions []extension.Value) {
	m.extensions = extensions
}

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
//	  [2 bytes]  extensions length (from extension.MarshalList)
//	  [variable] extensions data
func (m *MessageCertificate13) Marshal() ([]byte, error) {
	extensions, certsSize, marshalSize, err := m.prepareMarshal()
	if err != nil {
		return nil, err
	}

	out := make([]byte, marshalSize)
	m.marshalTo(out, extensions, certsSize)

	return out, nil
}

// MarshalSize returns the minimal size required for MarshalTo.
func (m *MessageCertificate13) MarshalSize() int {
	return 1 + len(m.CertificateRequestContext) + cert13CertLengthFieldSize + m.certsSize()
}

func (m *MessageCertificate13) certsSize() int {
	certificateListSize := 0
	for i := range m.CertificateList {
		entry := &m.CertificateList[i]
		certificateListSize += cert13CertLengthFieldSize
		certificateListSize += len(entry.CertificateData)
		certificateListSize += extension.MarshalListSize(entry.extensions)
	}

	return certificateListSize
}

// MarshalTo is same as Marshal but uses a pre-allocated buffer.
func (m *MessageCertificate13) MarshalTo(out []byte) (int, error) {
	extensions, certsSize, marshalSize, err := m.prepareMarshal()
	if err != nil {
		return 0, err
	}
	if len(out) < marshalSize {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	m.marshalTo(out, extensions, certsSize)

	return marshalSize, nil
}

func (m *MessageCertificate13) prepareMarshal() ([][]byte, int, int, error) {
	// Validate certificate_request_context length
	if len(m.CertificateRequestContext) > cert13ContextMaxLength {
		return nil, 0, 0, dtlserrors.ErrCertificateRequestContextTooLong
	}

	extensions := make([][]byte, len(m.CertificateList))
	certsSize := 0
	for i := range m.CertificateList {
		entry := &m.CertificateList[i]
		certDataLen := len(entry.CertificateData)
		if certDataLen == 0 || certDataLen > maxUint24 {
			return nil, 0, 0, dtlserrors.ErrInvalidCertificateEntry
		}

		encoded, err := extension.MarshalList(entry.extensions)
		if err != nil {
			return nil, 0, 0, err
		}
		extensions[i] = encoded

		entrySize := cert13CertLengthFieldSize + certDataLen + len(encoded)
		if entrySize > maxUint24-certsSize {
			return nil, 0, 0, dtlserrors.ErrCertificateListTooLong
		}
		certsSize += entrySize
	}

	marshalSize := cert13ContextLengthFieldSize + len(m.CertificateRequestContext) +
		cert13CertLengthFieldSize + certsSize

	return extensions, certsSize, marshalSize, nil
}

func (m *MessageCertificate13) marshalTo(out []byte, extensions [][]byte, certsSize int) {
	// Start with certificate_request_context (1-byte length prefix)
	//nolint:gosec // G115: certificate_request_context length is validated to be <= 255 above.
	offset := 0
	out[0] = byte(len(m.CertificateRequestContext)) //nolint:gosec // G115
	offset += 1
	offset += copy(out[offset:], m.CertificateRequestContext) //nolint:gosec // G115

	// Add certificate_list with 3-byte length prefix
	util.PutBigEndianUint24(out[offset:], uint32(certsSize)) //nolint:gosec // G115
	offset += 3

	// Build certificate_list
	for i := range m.CertificateList {
		entry := &m.CertificateList[i]

		// Add cert_data as a 3-byte length prefix
		certDataLen := len(entry.CertificateData)
		util.PutBigEndianUint24(out[offset:], uint32(certDataLen)) //nolint:gosec // G115
		offset += 3
		offset += copy(out[offset:], entry.CertificateData)

		offset += copy(out[offset:], extensions[i])
	}
}

// parseCertificate13Entry parses a single certificate entry from the cryptobyte string.
func parseCertificate13Entry(str *cryptobyte.String) (*CertificateEntry13, error) {
	// Read cert_data with 3-byte length prefix
	var certData cryptobyte.String
	if !str.ReadUint24LengthPrefixed(&certData) {
		return nil, dtlserrors.ErrInvalidCertificateEntry
	}

	// Validate cert_data length is in valid range <1..2^24-1>
	if len(certData) == 0 {
		return nil, dtlserrors.ErrInvalidCertificateEntry
	}

	// Copy cert_data to avoid aliasing issues
	certDataBytes := bytes.Clone(certData)

	// Validate extensions length (2-byte length prefix + up to 2^16-1 bytes of data)
	if len(*str) < cert13ExtLengthFieldSize {
		return nil, dtlserrors.ErrInvalidCertificateEntry
	}

	// Read extensions length to validate we have enough data
	extensionsLen := binary.BigEndian.Uint16([]byte(*str)[:cert13ExtLengthFieldSize])
	if len(*str) < cert13ExtLengthFieldSize+int(extensionsLen) {
		return nil, dtlserrors.ErrInvalidCertificateEntry
	}

	// Unmarshal extensions data
	extensionsData := []byte(*str)[:cert13ExtLengthFieldSize+int(extensionsLen)]
	extensions, err := decodeExtensionList(extensionsData, extensionContextCertificateEntry)
	if err != nil {
		return nil, err
	}

	// Advance the cryptobyte.String's position
	if !str.Skip(cert13ExtLengthFieldSize + int(extensionsLen)) {
		return nil, dtlserrors.ErrInvalidCertificateEntry
	}

	entry := &CertificateEntry13{CertificateData: certDataBytes}
	entry.SetExtensions(extensions)

	return entry, nil
}

// Unmarshal decodes the MessageCertificate13 from its wire format.
func (m *MessageCertificate13) Unmarshal(data []byte) error {
	// Validate minimum data length
	if len(data) < cert13ContextLengthFieldSize+cert13CertLengthFieldSize {
		return dtlserrors.ErrBufferTooSmall
	}

	str := cryptobyte.String(data)

	// Read certificate_request_context with 1-byte length prefix
	var contextData cryptobyte.String
	if !str.ReadUint8LengthPrefixed(&contextData) {
		return dtlserrors.ErrInvalidCertificateRequestContext
	}
	m.CertificateRequestContext = bytes.Clone(contextData)

	// Read certificate_list with 3-byte length prefix
	var certificateListData cryptobyte.String
	if !str.ReadUint24LengthPrefixed(&certificateListData) {
		return dtlserrors.ErrInvalidCertificateEntry
	}

	// Ensure no trailing data
	if len(str) != 0 {
		return dtlserrors.ErrLengthMismatch
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
