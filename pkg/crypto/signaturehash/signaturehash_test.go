// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package signaturehash

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		"PSSSchemes": {
			input: []tls.SignatureScheme{
				tls.PSSWithSHA256, // 0x0804 (RSAE variant)
				tls.PSSWithSHA384, // 0x0805 (RSAE variant)
				tls.PSSWithSHA512, // 0x0806 (RSAE variant)
			},
			expected: []Algorithm{
				{hash.SHA256, signature.RSA_PSS_RSAE_SHA256},
				{hash.SHA384, signature.RSA_PSS_RSAE_SHA384},
				{hash.SHA512, signature.RSA_PSS_RSAE_SHA512},
			},
			insecureHashes: false,
			err:            nil,
		},
		"MixedPSSAndNonPSS": {
			input: []tls.SignatureScheme{
				tls.PSSWithSHA256,          // PSS (RSAE)
				tls.PKCS1WithSHA256,        // Non-PSS RSA
				tls.ECDSAWithP256AndSHA256, // ECDSA
			},
			expected: []Algorithm{
				{hash.SHA256, signature.RSA_PSS_RSAE_SHA256},
				{hash.SHA256, signature.RSA},
				{hash.SHA256, signature.ECDSA},
			},
			insecureHashes: false,
			err:            nil,
		},
		"PSSPSSSchemes": {
			input: []tls.SignatureScheme{
				0x0809, // RSA_PSS_PSS_SHA256
				0x080a, // RSA_PSS_PSS_SHA384
				0x080b, // RSA_PSS_PSS_SHA512
			},
			expected: []Algorithm{
				{hash.SHA256, signature.RSA_PSS_PSS_SHA256},
				{hash.SHA384, signature.RSA_PSS_PSS_SHA384},
				{hash.SHA512, signature.RSA_PSS_PSS_SHA512},
			},
			insecureHashes: false,
			err:            nil,
		},
		"AllPSSVariants": {
			input: []tls.SignatureScheme{
				tls.PSSWithSHA256, // 0x0804 (RSAE)
				0x0809,            // RSA_PSS_PSS_SHA256
				tls.PSSWithSHA384, // 0x0805 (RSAE)
				0x080a,            // RSA_PSS_PSS_SHA384
				tls.PSSWithSHA512, // 0x0806 (RSAE)
				0x080b,            // RSA_PSS_PSS_SHA512
			},
			expected: []Algorithm{
				{hash.SHA256, signature.RSA_PSS_RSAE_SHA256},
				{hash.SHA256, signature.RSA_PSS_PSS_SHA256},
				{hash.SHA384, signature.RSA_PSS_RSAE_SHA384},
				{hash.SHA384, signature.RSA_PSS_PSS_SHA384},
				{hash.SHA512, signature.RSA_PSS_RSAE_SHA512},
				{hash.SHA512, signature.RSA_PSS_PSS_SHA512},
			},
			insecureHashes: false,
			err:            nil,
		},
		"Ed25519NotTreatedAsPSS": {
			input: []tls.SignatureScheme{
				tls.Ed25519, // 0x0807 - in 0x08xx range but NOT PSS
			},
			expected: []Algorithm{
				{hash.Ed25519, signature.Ed25519},
			},
			insecureHashes: false,
			err:            nil,
		},
		"InvalidPSSLikeScheme": {
			input: []tls.SignatureScheme{
				0x0808, // In PSS range but not a valid PSS scheme (this is Ed448 in reality)
			},
			expected:       nil,
			insecureHashes: false,
			err:            errInvalidSignatureAlgorithm,
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

func TestSelectSignatureScheme13_VersionAware(t *testing.T) {
	// Generate test keys
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name           string
		schemes        []Algorithm
		privateKey     crypto.PrivateKey
		is13           bool
		expectedSigAlg signature.Algorithm
		expectedError  error
	}{
		{
			name: "DTLS 1.3 with RSA key selects PSS",
			schemes: []Algorithm{
				{hash.SHA256, signature.RSA_PSS_RSAE_SHA256},
				{hash.SHA256, signature.RSA},
			},
			privateKey:     rsaKey,
			is13:           true,
			expectedSigAlg: signature.RSA_PSS_RSAE_SHA256,
			expectedError:  nil,
		},
		{
			name: "DTLS 1.2 with RSA key skips PSS, selects PKCS#1 v1.5",
			schemes: []Algorithm{
				{hash.SHA256, signature.RSA_PSS_RSAE_SHA256},
				{hash.SHA256, signature.RSA},
			},
			privateKey:     rsaKey,
			is13:           false,
			expectedSigAlg: signature.RSA,
			expectedError:  nil,
		},
		{
			name: "DTLS 1.2 with RSA key and only PSS schemes fails",
			schemes: []Algorithm{
				{hash.SHA256, signature.RSA_PSS_RSAE_SHA256},
				{hash.SHA384, signature.RSA_PSS_RSAE_SHA384},
			},
			privateKey:     rsaKey,
			is13:           false,
			expectedSigAlg: 0,
			expectedError:  errNoAvailableSignatureSchemes,
		},
		{
			name: "ECDSA works on both DTLS 1.2 and 1.3",
			schemes: []Algorithm{
				{hash.SHA256, signature.ECDSA},
			},
			privateKey:     ecdsaKey,
			is13:           false,
			expectedSigAlg: signature.ECDSA,
			expectedError:  nil,
		},
		{
			name: "DTLS 1.3 with RSA key skips RSA_PSS_PSS, selects RSA_PSS_RSAE",
			schemes: []Algorithm{
				{hash.SHA256, signature.RSA_PSS_PSS_SHA256},
				{hash.SHA256, signature.RSA_PSS_RSAE_SHA256},
				{hash.SHA256, signature.RSA},
			},
			privateKey:     rsaKey,
			is13:           true,
			expectedSigAlg: signature.RSA_PSS_RSAE_SHA256,
			expectedError:  nil,
		},
		{
			name: "DTLS 1.3 with RSA key and only RSA_PSS_PSS schemes falls back to PKCS#1 v1.5",
			schemes: []Algorithm{
				{hash.SHA256, signature.RSA_PSS_PSS_SHA256},
				{hash.SHA384, signature.RSA_PSS_PSS_SHA384},
				{hash.SHA256, signature.RSA},
			},
			privateKey:     rsaKey,
			is13:           true,
			expectedSigAlg: signature.RSA,
			expectedError:  nil,
		},
		{
			name: "DTLS 1.3 with RSA key and only RSA_PSS_PSS schemes fails if no fallback",
			schemes: []Algorithm{
				{hash.SHA256, signature.RSA_PSS_PSS_SHA256},
				{hash.SHA384, signature.RSA_PSS_PSS_SHA384},
				{hash.SHA512, signature.RSA_PSS_PSS_SHA512},
			},
			privateKey:     rsaKey,
			is13:           true,
			expectedSigAlg: 0,
			expectedError:  errNoAvailableSignatureSchemes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := selectSignatureScheme13(tt.schemes, tt.privateKey, tt.is13)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSigAlg, result.Signature)
			}
		})
	}
}

func TestFromCertificate(t *testing.T) {
	tests := []struct {
		name     string
		sigAlg   x509.SignatureAlgorithm
		expected Algorithm
		wantErr  bool
	}{
		{
			name:     "SHA256WithRSA",
			sigAlg:   x509.SHA256WithRSA,
			expected: Algorithm{Hash: hash.SHA256, Signature: signature.RSA},
			wantErr:  false,
		},
		{
			name:     "SHA384WithRSA",
			sigAlg:   x509.SHA384WithRSA,
			expected: Algorithm{Hash: hash.SHA384, Signature: signature.RSA},
			wantErr:  false,
		},
		{
			name:     "SHA512WithRSA",
			sigAlg:   x509.SHA512WithRSA,
			expected: Algorithm{Hash: hash.SHA512, Signature: signature.RSA},
			wantErr:  false,
		},
		{
			name:     "SHA256WithRSAPSS",
			sigAlg:   x509.SHA256WithRSAPSS,
			expected: Algorithm{Hash: hash.SHA256, Signature: signature.RSA},
			wantErr:  false,
		},
		{
			name:     "SHA384WithRSAPSS",
			sigAlg:   x509.SHA384WithRSAPSS,
			expected: Algorithm{Hash: hash.SHA384, Signature: signature.RSA},
			wantErr:  false,
		},
		{
			name:     "SHA512WithRSAPSS",
			sigAlg:   x509.SHA512WithRSAPSS,
			expected: Algorithm{Hash: hash.SHA512, Signature: signature.RSA},
			wantErr:  false,
		},
		{
			name:     "ECDSAWithSHA256",
			sigAlg:   x509.ECDSAWithSHA256,
			expected: Algorithm{Hash: hash.SHA256, Signature: signature.ECDSA},
			wantErr:  false,
		},
		{
			name:     "ECDSAWithSHA384",
			sigAlg:   x509.ECDSAWithSHA384,
			expected: Algorithm{Hash: hash.SHA384, Signature: signature.ECDSA},
			wantErr:  false,
		},
		{
			name:     "ECDSAWithSHA512",
			sigAlg:   x509.ECDSAWithSHA512,
			expected: Algorithm{Hash: hash.SHA512, Signature: signature.ECDSA},
			wantErr:  false,
		},
		{
			name:     "PureEd25519",
			sigAlg:   x509.PureEd25519,
			expected: Algorithm{Hash: hash.None, Signature: signature.Ed25519},
			wantErr:  false,
		},
		{
			name:     "SHA1WithRSA",
			sigAlg:   x509.SHA1WithRSA,
			expected: Algorithm{Hash: hash.SHA1, Signature: signature.RSA},
			wantErr:  false,
		},
		{
			name:     "ECDSAWithSHA1",
			sigAlg:   x509.ECDSAWithSHA1,
			expected: Algorithm{Hash: hash.SHA1, Signature: signature.ECDSA},
			wantErr:  false,
		},
		{
			name:     "MD5WithRSA (unsupported)",
			sigAlg:   x509.MD5WithRSA,
			expected: Algorithm{},
			wantErr:  true,
		},
		{
			name:     "MD2WithRSA (unsupported)",
			sigAlg:   x509.MD2WithRSA,
			expected: Algorithm{},
			wantErr:  true,
		},
		{
			name:     "UnknownSignatureAlgorithm",
			sigAlg:   x509.UnknownSignatureAlgorithm,
			expected: Algorithm{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FromCertificate(&x509.Certificate{SignatureAlgorithm: tt.sigAlg})
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, errInvalidSignatureAlgorithm)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
