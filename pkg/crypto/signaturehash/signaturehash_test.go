// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package signaturehash

import (
	"crypto/tls"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/stretchr/testify/assert"
)

func TestParseSignatureSchemes(t *testing.T) {
	cases := map[string]struct {
		input          []tls.SignatureScheme
		expected       []Algorithm
		err            error
		insecureHashes bool
	}{
		"Translate": {
			input: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.Ed25519,
			},
			expected: []Algorithm{
				{hash.SHA256, signature.ECDSA},
				{hash.SHA384, signature.ECDSA},
				{hash.SHA512, signature.ECDSA},
				{hash.SHA256, signature.RSA},
				{hash.SHA384, signature.RSA},
				{hash.SHA512, signature.RSA},
				{hash.Ed25519, signature.Ed25519},
			},
			insecureHashes: false,
			err:            nil,
		},
		"InvalidSignatureAlgorithm": {
			input: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256, // Valid
				0x04FF,                     // Invalid: unknown signature with SHA-256
			},
			expected:       nil,
			insecureHashes: false,
			err:            errInvalidSignatureAlgorithm,
		},
		"InvalidHashAlgorithm": {
			input: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256, // Valid
				0x0003,                     // Invalid: ECDSA with None
			},
			expected:       nil,
			insecureHashes: false,
			err:            errInvalidHashAlgorithm,
		},
		"InsecureHashAlgorithmDenied": {
			input: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256, // Valid
				tls.ECDSAWithSHA1,          // Insecure
			},
			expected: []Algorithm{
				{hash.SHA256, signature.ECDSA},
			},
			insecureHashes: false,
			err:            nil,
		},
		"InsecureHashAlgorithmAllowed": {
			input: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256, // Valid
				tls.ECDSAWithSHA1,          // Insecure
			},
			expected: []Algorithm{
				{hash.SHA256, signature.ECDSA},
				{hash.SHA1, signature.ECDSA},
			},
			insecureHashes: true,
			err:            nil,
		},
		"OnlyInsecureHashAlgorithm": {
			input: []tls.SignatureScheme{
				tls.ECDSAWithSHA1, // Insecure
			},
			insecureHashes: false,
			err:            errNoAvailableSignatureSchemes,
		},
	}

	for name, testCase := range cases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			output, err := ParseSignatureSchemes(testCase.input, testCase.insecureHashes)
			if testCase.err != nil {
				assert.ErrorIs(t, err, testCase.err)
			}
			assert.Equal(t, testCase.expected, output)
		})
	}
}
