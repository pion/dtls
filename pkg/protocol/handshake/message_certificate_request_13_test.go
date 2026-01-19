// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandshakeMessageCertificateRequest13(t *testing.T) {
	cases := map[string]struct {
		rawCertificateRequest    []byte
		parsedCertificateRequest *MessageCertificateRequest13
		expErr                   error
	}{
		"valid - no context, single signature algorithm": {
			rawCertificateRequest: []byte{
				0x00,       // context length = 0
				0x00, 0x08, // extensions length = 8
				0x00, 0x0D, // extension type = signature_algorithms (13)
				0x00, 0x04, // extension length = 4
				0x00, 0x02, // signature_algorithms length = 2
				0x04, 0x03, // ECDSA-SHA256
			},
			parsedCertificateRequest: &MessageCertificateRequest13{
				CertificateRequestContext: []byte{},
				Extensions: []extension.Extension{
					&extension.SupportedSignatureAlgorithms{
						SignatureHashAlgorithms: []signaturehash.Algorithm{
							{Hash: hash.SHA256, Signature: signature.ECDSA},
						},
					},
				},
			},
		},
		"valid - with context, multiple signature algorithms": {
			rawCertificateRequest: []byte{
				0x04,                   // context length = 4
				0x01, 0x02, 0x03, 0x04, // context data
				0x00, 0x0C, // extensions length = 12
				0x00, 0x0D, // extension type = signature_algorithms (13)
				0x00, 0x08, // extension length = 8
				0x00, 0x06, // signature_algorithms length = 6
				0x04, 0x03, // ECDSA-SHA256
				0x04, 0x01, // RSA-PKCS1-SHA256
				0x05, 0x03, // ECDSA-SHA384
			},
			parsedCertificateRequest: &MessageCertificateRequest13{
				CertificateRequestContext: []byte{0x01, 0x02, 0x03, 0x04},
				Extensions: []extension.Extension{
					&extension.SupportedSignatureAlgorithms{
						SignatureHashAlgorithms: []signaturehash.Algorithm{
							{Hash: hash.SHA256, Signature: signature.ECDSA},
							{Hash: hash.SHA256, Signature: signature.RSA},
							{Hash: hash.SHA384, Signature: signature.ECDSA},
						},
					},
				},
			},
		},
		"invalid - missing signature_algorithms": {
			rawCertificateRequest: []byte{
				0x00,       // context length = 0
				0x00, 0x00, // extensions length = 0
			},
			expErr: errMissingSignatureAlgorithmsExtension,
		},
		"invalid - buffer too small": {
			rawCertificateRequest: []byte{0x00},
			expErr:                errBufferTooSmall,
		},
	}

	for name, testCase := range cases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			c := &MessageCertificateRequest13{}
			err := c.Unmarshal(testCase.rawCertificateRequest)

			if testCase.expErr != nil {
				assert.ErrorIs(t, err, testCase.expErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, testCase.parsedCertificateRequest.CertificateRequestContext, c.CertificateRequestContext)
				assert.Equal(t, len(testCase.parsedCertificateRequest.Extensions), len(c.Extensions))

				raw, err := c.Marshal()
				assert.NoError(t, err)
				assert.Equal(t, testCase.rawCertificateRequest, raw)
			}
		})
	}
}

func TestMessageCertificateRequest13_Type(t *testing.T) {
	m := &MessageCertificateRequest13{}
	assert.Equal(t, TypeCertificateRequest, m.Type())
}

func TestMessageCertificateRequest13_MinimalValid(t *testing.T) {
	// Build (valid) message with empty context
	msg := &MessageCertificateRequest13{
		CertificateRequestContext: []byte{},
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
					{Hash: hash.SHA256, Signature: signature.RSA},
				},
			},
		},
	}
	marshalUnmarshalMessageCertificateRequest13AndVerifyMatch(t, msg)
}

func TestMessageCertificateRequest13_WithContext(t *testing.T) {
	// Build (valid) message with non-empty context
	msg := &MessageCertificateRequest13{
		CertificateRequestContext: []byte{0x01, 0x02, 0x03, 0x04},
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
				},
			},
		},
	}
	marshalUnmarshalMessageCertificateRequest13AndVerifyMatch(t, msg)
}

func TestMessageCertificateRequest13_MaxContextLength(t *testing.T) {
	// Build (valid) message with context of exactly the max size
	context := make([]byte, certReq13ContextMaxLength)
	for i := range context {
		context[i] = byte(i)
	}
	msg := &MessageCertificateRequest13{
		CertificateRequestContext: context,
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
				},
			},
		},
	}
	marshalUnmarshalMessageCertificateRequest13AndVerifyMatch(t, msg)
}

func TestMessageCertificateRequest13_MultipleExtensions(t *testing.T) {
	// Build (valid) message with multiple extensions
	// (signature_algorithms, which must be present, and server_name)
	msg := &MessageCertificateRequest13{
		CertificateRequestContext: []byte{0x01, 0x02, 0x03, 0x04},
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
					{Hash: hash.SHA384, Signature: signature.ECDSA},
					{Hash: hash.SHA512, Signature: signature.RSA},
				},
			},
			&extension.ServerName{ServerName: "example.com"},
		},
	}
	marshalUnmarshalMessageCertificateRequest13AndVerifyMatch(t, msg)
}

func TestMessageCertificateRequest13_ContextTooLong(t *testing.T) {
	// Build (invalid) message with context exceeding the max size
	tooLongContext := make([]byte, certReq13ContextMaxLength+1)
	msg := &MessageCertificateRequest13{
		CertificateRequestContext: tooLongContext,
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
				},
			},
		},
	}

	_, err := msg.Marshal()
	assert.ErrorIs(t, err, errCertificateRequestContextTooLong)
}

func TestMessageCertificateRequest13_MissingSignatureAlgorithms(t *testing.T) {
	// Build (invalid) message with no signature_algorithms extension
	msg := &MessageCertificateRequest13{}

	_, err := msg.Marshal()
	assert.ErrorIs(t, err, errMissingSignatureAlgorithmsExtension)
}

func TestMessageCertificateRequest13_UnmarshalMissingSignatureAlgorithms(t *testing.T) {
	// Define (invalid) serialized message (has no signature_algorithms extension)
	data := []byte{
		0x00,       // context length = 0
		0x00, 0x00, // extensions length = 0
	}

	err := (&MessageCertificateRequest13{}).Unmarshal(data)
	assert.ErrorIs(t, err, errMissingSignatureAlgorithmsExtension)
}

func TestMessageCertificateRequest13_UnmarshalBufferTooSmall(t *testing.T) {
	// Define (invalid) serialized messages (data too small)
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"1 byte", []byte{0x00}},
		{"2 bytes", []byte{0x00, 0x00}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := (&MessageCertificateRequest13{}).Unmarshal(test.data)
			assert.Error(t, err)
		})
	}
}

func TestMessageCertificateRequest13_UnmarshalInvalidContext(t *testing.T) {
	// Define (invalid) serialized message (data smaller than advertised context length)
	data := []byte{
		0x05,                   // context length = 5
		0x01, 0x02, 0x03, 0x04, // only 2 bytes
	}

	err := (&MessageCertificateRequest13{}).Unmarshal(data)
	assert.ErrorIs(t, err, errInvalidCertificateRequestContext)
}

func TestMessageCertificateRequest13_UnmarshalInvalidExtensions(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		// Define (invalid) serialized message (data smaller than advertised context length)
		{
			name: "only 1 byte of extensions after context",
			data: []byte{
				0x01, // context length = 1
				0xFF, // context data
				0x00, // only 1 byte of extensions (< 2 bytes required)
			},
		},
		// Define (invalid) serialized message (extensions length bytes truncated)
		{
			name: "no extensions after empty context",
			data: []byte{
				0x02,       // context length = 2
				0x01, 0x02, // context data
				0x00, // only 1 byte of extensions (< 2 bytes required)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := (&MessageCertificateRequest13{}).Unmarshal(test.data)
			assert.ErrorIs(t, err, errInvalidExtensionsLength)
		})
	}
}

func FuzzMessageCertificateRequest13(f *testing.F) {
	// Seed with valid minimal message (signature_algorithms extension)
	f.Add([]byte{
		0x00,       // context length = 0
		0x00, 0x06, // extensions length = 6
		0x00, 0x0D, // extension type = signature_algorithms (13)
		0x00, 0x02, // extension length = 2
		0x04, 0x03, // ECDSA-SHA256
	})

	// Seed with valid message with context
	f.Add([]byte{
		0x04,                   // context length = 4
		0x01, 0x02, 0x03, 0x04, // context data
		0x00, 0x06, // extensions length = 6
		0x00, 0x0D, // extension type = signature_algorithms (13)
		0x00, 0x02, // extension length = 2
		0x04, 0x03, // ECDSA-SHA256
	})

	// Seed with valid message with multiple signature algorithms
	f.Add([]byte{
		0x00,       // context length = 0
		0x00, 0x0A, // extensions length = 10
		0x00, 0x0D, // extension type = signature_algorithms (13)
		0x00, 0x06, // extension length = 6
		0x04, 0x03, // ECDSA-SHA256
		0x08, 0x04, // RSA-PSS-RSAE-SHA256
		0x08, 0x05, // RSA-PSS-RSAE-SHA384
	})

	// Seed with invalid data for edge case testing
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = (&MessageCertificateRequest13{}).Unmarshal(data)
	})
}

// marshalUnmarshalMessageCertificateRequest13AndVerifyMatch marshals and
// unmarshals a MessageCertificateRequest13, then verifies that the message
// before and after have matching properties.
func marshalUnmarshalMessageCertificateRequest13AndVerifyMatch(
	t *testing.T,
	in *MessageCertificateRequest13,
) {
	t.Helper()

	out := &MessageCertificateRequest13{}

	// Marshal, then unmarshal
	marshaled, err := in.Marshal()
	require.NoError(t, err)
	err = out.Unmarshal(marshaled)
	require.NoError(t, err)

	// Verify before/after marshal/unmarshal match
	assert.Equal(t, in.CertificateRequestContext, out.CertificateRequestContext)
	assert.EqualValues(t, in.Extensions, out.Extensions)

	// Verify has signature algorithms extension present
	hasSignatureAlgorithms := false
	for _, ext := range out.Extensions {
		if ext.TypeValue() == extension.SupportedSignatureAlgorithmsTypeValue {
			hasSignatureAlgorithms = true

			break
		}
	}
	assert.True(t, hasSignatureAlgorithms)
}
