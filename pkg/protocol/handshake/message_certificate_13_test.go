// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

func TestHandshakeMessageCertificate13(t *testing.T) {
	// This is the same certificate from TestHandshakeMessageCertificate (DTLS 1.2)
	certDER := []byte{
		0x30, 0x82, 0x01, 0x85, 0x30, 0x82, 0x01, 0x2b, 0x02, 0x14,
		0x7d, 0x00, 0xcf, 0x07, 0xfc, 0xe2, 0xb6, 0xb8, 0x3f, 0x72, 0xeb, 0x11, 0x36, 0x1b, 0xf6, 0x39,
		0xf1, 0x3c, 0x33, 0x41, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
		0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31,
		0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53,
		0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49,
		0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20,
		0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38, 0x31, 0x30, 0x32,
		0x35, 0x30, 0x38, 0x35, 0x31, 0x31, 0x32, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x31, 0x30, 0x32, 0x35,
		0x30, 0x38, 0x35, 0x31, 0x31, 0x32, 0x5a, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
		0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
		0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06,
		0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57,
		0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x59,
		0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
		0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xf9, 0xb1, 0x62, 0xd6, 0x07, 0xae, 0xc3,
		0x36, 0x34, 0xf5, 0xa3, 0x09, 0x39, 0x86, 0xe7, 0x3b, 0x59, 0xf7, 0x4a, 0x1d, 0xf4, 0x97, 0x4f,
		0x91, 0x40, 0x56, 0x1b, 0x3d, 0x6c, 0x5a, 0x38, 0x10, 0x15, 0x58, 0xf5, 0xa4, 0xcc, 0xdf, 0xd5,
		0xf5, 0x4a, 0x35, 0x40, 0x0f, 0x9f, 0x54, 0xb7, 0xe9, 0xe2, 0xae, 0x63, 0x83, 0x6a, 0x4c, 0xfc,
		0xc2, 0x5f, 0x78, 0xa0, 0xbb, 0x46, 0x54, 0xa4, 0xda, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
		0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x47, 0x1a, 0x5f, 0x58,
		0x2a, 0x74, 0x33, 0x6d, 0xed, 0xac, 0x37, 0x21, 0xfa, 0x76, 0x5a, 0x4d, 0x78, 0x68, 0x1a, 0xdd,
		0x80, 0xa4, 0xd4, 0xb7, 0x7f, 0x7d, 0x78, 0xb3, 0xfb, 0xf3, 0x95, 0xfb, 0x02, 0x21, 0x00, 0xc0,
		0x73, 0x30, 0xda, 0x2b, 0xc0, 0x0c, 0x9e, 0xb2, 0x25, 0x0d, 0x46, 0xb0, 0xbc, 0x66, 0x7f, 0x71,
		0x66, 0xbf, 0x16, 0xb3, 0x80, 0x78, 0xd0, 0x0c, 0xef, 0xcc, 0xf5, 0xc1, 0x15, 0x0f, 0x58,
	}

	tests := map[string]struct {
		rawCertificate    []byte
		parsedCertificate *MessageCertificate13
		expErr            error
	}{
		"valid - no context, single cert, no extensions": {
			rawCertificate: append([]byte{
				0x00,             // context length = 0
				0x00, 0x01, 0x8E, // certificate_list length = 398 (3 + 393 + 2)
				0x00, 0x01, 0x89, // cert_data length = 393
			}, append(certDER, []byte{0x00, 0x00}...)...), // cert_data + extensions length = 0
			parsedCertificate: &MessageCertificate13{
				CertificateRequestContext: []byte{},
				CertificateList: []CertificateEntry13{
					{
						CertificateData: certDER,
						Extensions:      []extension.Extension{},
					},
				},
			},
		},
		"valid - with context, single cert, no extensions": {
			rawCertificate: append([]byte{
				0x02,       // context length = 2
				0x01, 0x02, // context data
				0x00, 0x01, 0x8E, // certificate_list length = 398 (3 + 393 + 2)
				0x00, 0x01, 0x89, // cert_data length = 393
			}, append(certDER, []byte{0x00, 0x00}...)...), // cert_data + extensions length = 0
			parsedCertificate: &MessageCertificate13{
				CertificateRequestContext: []byte{0x01, 0x02},
				CertificateList: []CertificateEntry13{
					{
						CertificateData: certDER,
						Extensions:      []extension.Extension{},
					},
				},
			},
		},
		"valid - no context, empty cert list": {
			rawCertificate: []byte{
				0x00,             // context length = 0
				0x00, 0x00, 0x00, // certificate_list length = 0
			},
			parsedCertificate: &MessageCertificate13{
				CertificateRequestContext: []byte{},
				CertificateList:           []CertificateEntry13{},
			},
		},
		"invalid - buffer too small": {
			rawCertificate: []byte{0x00},
			expErr:         errBufferTooSmall,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			cert := &MessageCertificate13{}
			err := cert.Unmarshal(test.rawCertificate)

			if test.expErr != nil {
				assert.ErrorIs(t, err, test.expErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.parsedCertificate.CertificateRequestContext, cert.CertificateRequestContext)
				assert.Equal(t, len(test.parsedCertificate.CertificateList), len(cert.CertificateList))

				// Verify certificate can be parsed
				if len(cert.CertificateList) > 0 {
					cert, err := x509.ParseCertificate(cert.CertificateList[0].CertificateData)
					assert.NoError(t, err)
					assert.Equal(t, x509.ECDSAWithSHA256, cert.SignatureAlgorithm)
				}

				raw, err := cert.Marshal()
				assert.NoError(t, err)
				assert.Equal(t, test.rawCertificate, raw)
			}
		})
	}
}

func TestMessageCertificate13_Type(t *testing.T) {
	m := &MessageCertificate13{}
	assert.Equal(t, TypeCertificate, m.Type())
}

func TestMessageCertificate13_SingleCertNoExtensions(t *testing.T) {
	// Build (valid) message with a real DER-encoded certificate
	msg := &MessageCertificate13{
		CertificateRequestContext: []byte{0x01, 0x02, 0x03, 0x04},
		CertificateList: []CertificateEntry13{
			{
				CertificateData: []byte{
					0x30, 0x82, 0x01, 0x85, 0x30, 0x82, 0x01, 0x2b, 0x02, 0x14,
					0x7d, 0x00, 0xcf, 0x07, 0xfc, 0xe2, 0xb6, 0xb8, 0x3f, 0x72, 0xeb, 0x11, 0x36, 0x1b, 0xf6, 0x39,
					0xf1, 0x3c, 0x33, 0x41, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
					0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31,
					0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53,
					0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49,
					0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20,
					0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38, 0x31, 0x30, 0x32,
					0x35, 0x30, 0x38, 0x35, 0x31, 0x31, 0x32, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x31, 0x30, 0x32, 0x35,
					0x30, 0x38, 0x35, 0x31, 0x31, 0x32, 0x5a, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
					0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
					0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06,
					0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57,
					0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x59,
					0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
					0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xf9, 0xb1, 0x62, 0xd6, 0x07, 0xae, 0xc3,
					0x36, 0x34, 0xf5, 0xa3, 0x09, 0x39, 0x86, 0xe7, 0x3b, 0x59, 0xf7, 0x4a, 0x1d, 0xf4, 0x97, 0x4f,
					0x91, 0x40, 0x56, 0x1b, 0x3d, 0x6c, 0x5a, 0x38, 0x10, 0x15, 0x58, 0xf5, 0xa4, 0xcc, 0xdf, 0xd5,
					0xf5, 0x4a, 0x35, 0x40, 0x0f, 0x9f, 0x54, 0xb7, 0xe9, 0xe2, 0xae, 0x63, 0x83, 0x6a, 0x4c, 0xfc,
					0xc2, 0x5f, 0x78, 0xa0, 0xbb, 0x46, 0x54, 0xa4, 0xda, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
					0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x47, 0x1a, 0x5f, 0x58,
					0x2a, 0x74, 0x33, 0x6d, 0xed, 0xac, 0x37, 0x21, 0xfa, 0x76, 0x5a, 0x4d, 0x78, 0x68, 0x1a, 0xdd,
					0x80, 0xa4, 0xd4, 0xb7, 0x7f, 0x7d, 0x78, 0xb3, 0xfb, 0xf3, 0x95, 0xfb, 0x02, 0x21, 0x00, 0xc0,
					0x73, 0x30, 0xda, 0x2b, 0xc0, 0x0c, 0x9e, 0xb2, 0x25, 0x0d, 0x46, 0xb0, 0xbc, 0x66, 0x7f, 0x71,
					0x66, 0xbf, 0x16, 0xb3, 0x80, 0x78, 0xd0, 0x0c, 0xef, 0xcc, 0xf5, 0xc1, 0x15, 0x0f, 0x58,
				},
				Extensions: []extension.Extension{},
			},
		},
	}

	out := &MessageCertificate13{}
	marshalUnmarshalMessageCertificate13AndVerifyMatch(t, msg, out)

	// Verify certificate is valid
	cert, err := x509.ParseCertificate(out.CertificateList[0].CertificateData)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSAWithSHA256, cert.SignatureAlgorithm)
}

func TestMessageCertificate13_WithContext(t *testing.T) {
	// Build (valid) message with non empty context
	msg := &MessageCertificate13{
		CertificateRequestContext: []byte{0x01, 0x02, 0x03, 0x04},
		CertificateList: []CertificateEntry13{
			{
				CertificateData: []byte{0xDE, 0xAD, 0xBE, 0xEF},
				Extensions:      []extension.Extension{},
			},
		},
	}
	marshalUnmarshalMessageCertificate13AndVerifyMatch(t, msg, nil)
}

func TestMessageCertificate13_MultipleCertificates(t *testing.T) {
	// Build (valid) message with multiple certificates
	msg := &MessageCertificate13{
		CertificateRequestContext: []byte{},
		CertificateList: []CertificateEntry13{
			{CertificateData: []byte{0x01, 0x02, 0x03}, Extensions: []extension.Extension{}},
			{CertificateData: []byte{0x04, 0x05, 0x06, 0x07}, Extensions: []extension.Extension{}},
			{CertificateData: []byte{0x08, 0x09}, Extensions: []extension.Extension{}},
		},
	}
	marshalUnmarshalMessageCertificate13AndVerifyMatch(t, msg, nil)
}

func TestMessageCertificate13_MaxContextLength(t *testing.T) {
	// Build (valid) message with context of exactly the max size
	context := make([]byte, cert13ContextMaxLength)
	for i := range context {
		context[i] = byte(i)
	}
	msg := &MessageCertificate13{
		CertificateRequestContext: context,
		CertificateList: []CertificateEntry13{
			{CertificateData: []byte{0x00}, Extensions: []extension.Extension{}},
		},
	}
	marshalUnmarshalMessageCertificate13AndVerifyMatch(t, msg, nil)
}

func TestMessageCertificate13_EmptyCertificateList(t *testing.T) {
	// Build (valid) message with empty certificate list (empty
	// certificate list is technically valid in DTLS 1.3 e.g.
	// when client has no suitable certificate)
	msg := &MessageCertificate13{
		CertificateRequestContext: []byte{},
		CertificateList:           []CertificateEntry13{},
	}
	marshalUnmarshalMessageCertificate13AndVerifyMatch(t, msg, nil)
}

func TestMessageCertificate13_ContextTooLong(t *testing.T) {
	// Build (invalid) message with context exceeding the max size
	context := make([]byte, cert13ContextMaxLength+1)
	msg := &MessageCertificate13{
		CertificateRequestContext: context,
		CertificateList: []CertificateEntry13{
			{CertificateData: []byte{0x00}, Extensions: nil},
		},
	}

	_, err := msg.Marshal()
	assert.ErrorIs(t, err, errCertificateRequestContextTooLong)
}

func TestMessageCertificate13_EmptyCertData(t *testing.T) {
	// Build (invalid) message with empty certificate data
	msg := &MessageCertificate13{
		CertificateRequestContext: []byte{},
		CertificateList: []CertificateEntry13{
			{CertificateData: []byte{}, Extensions: []extension.Extension{}},
		},
	}

	_, err := msg.Marshal()
	assert.ErrorIs(t, err, errInvalidCertificateEntry)
}

func TestMessageCertificate13_UnmarshalBufferTooSmall(t *testing.T) {
	// Define (invalid) serialized messages (data too small)
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"1 byte", []byte{0x00}},
		{"2 bytes", []byte{0x00, 0x00}},
		{"3 bytes", []byte{0x00, 0x00, 0x00}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := (&MessageCertificate13{}).Unmarshal(test.data)
			assert.ErrorIs(t, err, errBufferTooSmall)
		})
	}
}

func TestMessageCertificate13_UnmarshalLengthMismatch(t *testing.T) {
	// Define (invalid) serialized message (certificate_list
	// length says 10, but only 5 bytes follow)
	data := []byte{
		0x00,             // context length = 0
		0x00, 0x00, 0x0A, // certificate_list length = 10
		0x00, 0x00, 0x00, 0x00, 0x00, // only 5 bytes
	}

	err := (&MessageCertificate13{}).Unmarshal(data)
	// With cryptobyte, this will fail when trying to read the certificate_list
	assert.ErrorIs(t, err, errInvalidCertificateEntry)
}

func TestMessageCertificate13_UnmarshalInvalidCertEntry(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		// Define (invalid) serialized message (cert_data length is 10, but only 4 bytes follow)
		{
			name: "cert_data length mismatch",
			data: []byte{
				0x00,             // context length = 0
				0x00, 0x00, 0x07, // certificate_list length = 7
				0x00, 0x00, 0x0A, // cert_data length = 10 (invalid)
				0xDE, 0xAD, 0xBE, 0xEF, // only 4 bytes
			},
		},
		// Define (invalid) serialized message (cert_data length is 0)
		{
			name: "empty cert_data",
			data: []byte{
				0x00,             // context length = 0
				0x00, 0x00, 0x05, // certificate_list length = 5
				0x00, 0x00, 0x00, // cert_data length = 0 (invalid - must be >= 1)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := (&MessageCertificate13{}).Unmarshal(test.data)
			assert.ErrorIs(t, err, errInvalidCertificateEntry)
		})
	}
}

func TestParseCertificateEntry_GeneratedCertificate(t *testing.T) {
	// Generate ECDSA key-pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create a self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Construct the wire format for parseCertificateEntry
	// [3 bytes] cert_data length
	// [variable] cert_data
	// [2 bytes] extensions length (0 for this test)
	data := make([]byte, 0)

	// Add cert_data length (3 bytes, big-endian)
	certLen := len(certDER)
	data = append(data, byte(certLen>>16), byte(certLen>>8), byte(certLen))
	data = append(data, certDER...) // Add cert_data
	data = append(data, 0x00, 0x00) // Add extensions length = 0

	// Parse the certificate entry
	str := cryptobyte.String(data)
	entry, err := parseCertificate13Entry(&str)
	require.NoError(t, err)
	assert.Equal(t, 0, len(str)) // Ensure all data was consumed
	assert.Equal(t, certDER, entry.CertificateData)
	assert.Equal(t, 0, len(entry.Extensions))

	// Verify we can parse it back as a valid X.509 certificate
	parsedCert, err := x509.ParseCertificate(entry.CertificateData)
	require.NoError(t, err)
	assert.Equal(t, "test.example.com", parsedCert.Subject.CommonName)
	assert.Equal(t, "Test Org", parsedCert.Subject.Organization[0])
}

func TestParseCertificateEntry_GeneratedCertificateWithExtensions(t *testing.T) {
	// Generate ECDSA key-pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Org 2"},
			CommonName:   "test2.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Create extensions for the certificate entry
	serverName := &extension.ServerName{ServerName: "test2.example.com"}
	extensions := []extension.Extension{serverName}
	extensionsData, err := extension.Marshal(extensions)
	require.NoError(t, err)

	// Construct wire format
	data := make([]byte, 0)

	// Add cert_data length (3 bytes)
	certLen := len(certDER)
	data = append(data, byte(certLen>>16), byte(certLen>>8), byte(certLen))
	data = append(data, certDER...)        // Add cert_data
	data = append(data, extensionsData...) // Add extensions (incl. 2-byte prefix)

	// Parse it
	str := cryptobyte.String(data)
	entry, err := parseCertificate13Entry(&str)
	require.NoError(t, err)
	assert.Equal(t, 0, len(str)) // Ensure all data was consumed
	assert.Equal(t, certDER, entry.CertificateData)
	assert.Equal(t, 1, len(entry.Extensions))
	assert.Equal(t, extension.ServerNameTypeValue, entry.Extensions[0].TypeValue())

	// Verify the certificate is valid
	parsedCert, err := x509.ParseCertificate(entry.CertificateData)
	require.NoError(t, err)
	assert.Equal(t, "test2.example.com", parsedCert.Subject.CommonName)
	assert.Equal(t, x509.RSA, parsedCert.PublicKeyAlgorithm)
}

func FuzzMessageCertificate13(f *testing.F) {
	// Seed with valid minimal message (empty context, empty cert list)
	f.Add([]byte{
		0x00,             // context length = 0
		0x00, 0x00, 0x00, // certificate_list length = 0
	})

	// Seed with valid message with context
	f.Add([]byte{
		0x04,                   // context length = 4
		0x01, 0x02, 0x03, 0x04, // context data
		0x00, 0x00, 0x00, // certificate_list length = 0
	})

	// Seed with valid message with single cert (no extensions)
	f.Add([]byte{
		0x00,             // context length = 0
		0x00, 0x00, 0x07, // certificate_list length = 7
		0x00, 0x00, 0x03, // cert_data length = 3
		0xDE, 0xAD, 0xBE, // cert_data
		0x00, 0x00, // extensions length = 0
	})

	// Seed with invalid data for edge case testing
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = (&MessageCertificate{}).Unmarshal(data)
	})
}

// marshalUnmarshalMessageCertificate13AndVerifyMatch marshals and
// unmarshals a MessageCertificate13, then verifies that the message
// before and after have matching properties.
func marshalUnmarshalMessageCertificate13AndVerifyMatch(
	t *testing.T,
	in *MessageCertificate13,
	out *MessageCertificate13,
) {
	t.Helper()

	if out == nil {
		out = &MessageCertificate13{}
	}

	// Marshal, then unmarshal
	marshaled, err := in.Marshal()
	require.NoError(t, err)
	err = out.Unmarshal(marshaled)
	require.NoError(t, err)

	// Verify before/after marshal/unmarshal match
	assert.Equal(t, in.CertificateRequestContext, out.CertificateRequestContext)
	assert.EqualValues(t, in.CertificateList, out.CertificateList)
}
