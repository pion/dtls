// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/stretchr/testify/assert"
)

func TestSignatureAlgorithmsCert(t *testing.T) {
	rawSignatureAlgorithmsCert := []byte{
		0x00, 0x32, // Extension type: signature_algorithms_cert (50)
		0x00, 0x08, // Extension length: 8 bytes
		0x00, 0x06, // Signature Hash Algorithms Length: 6 bytes
		0x04, 0x03, // SHA256, ECDSA
		0x05, 0x03, // SHA384, ECDSA
		0x06, 0x03, // SHA512, ECDSA
	}
	parsedSignatureAlgorithmsCert := &SignatureAlgorithmsCert{
		SignatureHashAlgorithms: []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.ECDSA},
			{Hash: hash.SHA384, Signature: signature.ECDSA},
			{Hash: hash.SHA512, Signature: signature.ECDSA},
		},
	}

	raw, err := parsedSignatureAlgorithmsCert.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawSignatureAlgorithmsCert, raw, "SignatureAlgorithmsCert marshal")

	ext := &SignatureAlgorithmsCert{}
	err = ext.Unmarshal(rawSignatureAlgorithmsCert)
	assert.NoError(t, err)
	assert.Equal(t, parsedSignatureAlgorithmsCert, ext, "SignatureAlgorithmsCert unmarshal")
}

func TestSignatureAlgorithmsCertTypeValue(t *testing.T) {
	ext := &SignatureAlgorithmsCert{}
	assert.Equal(t, SignatureAlgorithmsCertTypeValue, ext.TypeValue(), "SignatureAlgorithmsCert TypeValue")
	assert.Equal(t, TypeValue(50), ext.TypeValue(), "SignatureAlgorithmsCert TypeValue should be 50")
}

func TestSignatureAlgorithmsCertPSSSchemes(t *testing.T) {
	// Test PSS schemes using full uint16 encoding (TLS 1.3 style)
	rawExtensionWithPSS := []byte{
		0x00, 0x32, // Extension type: signature_algorithms_cert (50)
		0x00, 0x08, // Extension length (8 bytes)
		0x00, 0x06, // Algorithms length (6 bytes = 3 schemes)
		0x08, 0x04, // RSA_PSS_RSAE_SHA256 (0x0804)
		0x08, 0x05, // RSA_PSS_RSAE_SHA384 (0x0805)
		0x08, 0x09, // RSA_PSS_PSS_SHA256 (0x0809)
	}
	parsedExtensionWithPSS := &SignatureAlgorithmsCert{
		SignatureHashAlgorithms: []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.RSA_PSS_RSAE_SHA256},
			{Hash: hash.SHA384, Signature: signature.RSA_PSS_RSAE_SHA384},
			{Hash: hash.SHA256, Signature: signature.RSA_PSS_PSS_SHA256},
		},
	}

	// Test Marshal
	raw, err := parsedExtensionWithPSS.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawExtensionWithPSS, raw)

	// Test Unmarshal
	roundtrip := &SignatureAlgorithmsCert{}
	assert.NoError(t, roundtrip.Unmarshal(raw))
	assert.Equal(t, parsedExtensionWithPSS, roundtrip)
}

func TestSignatureAlgorithmsCertMixedPSSAndNonPSS(t *testing.T) {
	// Test mixed PSS and non-PSS schemes
	rawExtensionMixed := []byte{
		0x00, 0x32, // Extension type: signature_algorithms_cert (50)
		0x00, 0x0a, // Extension length (10 bytes)
		0x00, 0x08, // Algorithms length (8 bytes = 4 schemes)
		0x08, 0x04, // RSA_PSS_RSAE_SHA256 (0x0804) - PSS
		0x04, 0x01, // RSA PKCS#1 with SHA256 - Non-PSS
		0x04, 0x03, // ECDSA with SHA256 - Non-PSS
		0x08, 0x07, // Ed25519 (0x0807) - Not PSS despite being in 0x08xx range
	}
	parsedExtensionMixed := &SignatureAlgorithmsCert{
		SignatureHashAlgorithms: []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.RSA_PSS_RSAE_SHA256},
			{Hash: hash.SHA256, Signature: signature.RSA},
			{Hash: hash.SHA256, Signature: signature.ECDSA},
			{Hash: hash.Ed25519, Signature: signature.Ed25519},
		},
	}

	// Test Marshal
	raw, err := parsedExtensionMixed.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawExtensionMixed, raw)

	// Test Unmarshal
	roundtrip := &SignatureAlgorithmsCert{}
	assert.NoError(t, roundtrip.Unmarshal(raw))
	assert.Equal(t, parsedExtensionMixed, roundtrip)
}

func TestSignatureAlgorithmsCertRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		ext  *SignatureAlgorithmsCert
	}{
		{
			name: "Empty",
			ext: &SignatureAlgorithmsCert{
				SignatureHashAlgorithms: []signaturehash.Algorithm{},
			},
		},
		{
			name: "Single algorithm",
			ext: &SignatureAlgorithmsCert{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.RSA},
				},
			},
		},
		{
			name: "Multiple algorithms",
			ext: &SignatureAlgorithmsCert{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.RSA},
					{Hash: hash.SHA384, Signature: signature.ECDSA},
					{Hash: hash.SHA512, Signature: signature.Ed25519},
				},
			},
		},
		{
			name: "RSA-PSS algorithms",
			ext: &SignatureAlgorithmsCert{
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.RSA_PSS_RSAE_SHA256},
					{Hash: hash.SHA384, Signature: signature.RSA_PSS_RSAE_SHA384},
					{Hash: hash.SHA512, Signature: signature.RSA_PSS_RSAE_SHA512},
				},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			raw, err := tc.ext.Marshal()
			assert.NoError(t, err, "Failed to marshal")

			parsed := &SignatureAlgorithmsCert{}
			err = parsed.Unmarshal(raw)
			assert.NoError(t, err, "Failed to unmarshal")

			assert.Equal(t, tc.ext, parsed, "Round trip failed")
		})
	}
}

func TestSignatureAlgorithmsCertUnmarshalErrors(t *testing.T) {
	t.Run("Empty data", func(t *testing.T) {
		ext := &SignatureAlgorithmsCert{}
		err := ext.Unmarshal([]byte{})
		assert.ErrorIs(t, err, errInvalidExtensionType)
	})

	t.Run("Invalid extension type", func(t *testing.T) {
		ext := &SignatureAlgorithmsCert{}
		err := ext.Unmarshal([]byte{
			0x00, 0x0D, // Wrong extension type (13 instead of 50)
			0x00, 0x04,
			0x00, 0x02,
			0x04, 0x03,
		})
		assert.ErrorIs(t, err, errInvalidExtensionType)
	})

	t.Run("Buffer too small - missing extension length", func(t *testing.T) {
		ext := &SignatureAlgorithmsCert{}
		err := ext.Unmarshal([]byte{
			0x00, 0x32, // Correct extension type
		})
		assert.ErrorIs(t, err, errBufferTooSmall)
	})

	t.Run("Buffer too small - missing algorithms length", func(t *testing.T) {
		ext := &SignatureAlgorithmsCert{}
		err := ext.Unmarshal([]byte{
			0x00, 0x32, // Extension type
			0x00, 0x02, // Extension length
		})
		assert.ErrorIs(t, err, errBufferTooSmall)
	})

	t.Run("Truncated algorithm list", func(t *testing.T) {
		ext := &SignatureAlgorithmsCert{}
		err := ext.Unmarshal([]byte{
			0x00, 0x32, // Extension type
			0x00, 0x06, // Extension length: 6 bytes
			0x00, 0x04, // Algorithms length: 4 bytes
			0x04, 0x03, // SHA256, ECDSA
			0x05, // Incomplete second algorithm
		})
		assert.ErrorIs(t, err, errBufferTooSmall)
	})

	t.Run("Length mismatch - declared length too long", func(t *testing.T) {
		ext := &SignatureAlgorithmsCert{}
		err := ext.Unmarshal([]byte{
			0x00, 0x32, // Extension type
			0x00, 0x06, // Extension length: 6 bytes
			0x00, 0x06, // Algorithms length: 6 bytes (but only 2 bytes of data follow)
			0x04, 0x03, // SHA256, ECDSA
		})
		assert.ErrorIs(t, err, errBufferTooSmall)
	})

	t.Run("Empty extension data", func(t *testing.T) {
		ext := &SignatureAlgorithmsCert{}
		err := ext.Unmarshal([]byte{
			0x00, 0x32, // Extension type
			0x00, 0x00, // Extension length: 0
		})
		assert.ErrorIs(t, err, errLengthMismatch)
	})
}

func TestSignatureAlgorithmsCertUnmarshalFiltering(t *testing.T) {
	// Test that invalid algorithms are filtered out during unmarshal
	rawData := []byte{
		0x00, 0x32, // Extension type: signature_algorithms_cert (50)
		0x00, 0x0A, // Extension length: 10 bytes
		0x00, 0x08, // Signature Hash Algorithms Length: 8 bytes
		0x04, 0x03, // Valid: SHA256, ECDSA
		0xFF, 0xFF, // Invalid: unknown hash and signature
		0x05, 0x03, // Valid: SHA384, ECDSA
		0x04, 0xFF, // Invalid: SHA256 with unknown signature
	}

	ext := &SignatureAlgorithmsCert{}
	err := ext.Unmarshal(rawData)
	assert.NoError(t, err)

	// Should only have the two valid algorithms (invalid ones filtered out)
	assert.Len(t, ext.SignatureHashAlgorithms, 2)
	assert.Equal(t, hash.SHA256, ext.SignatureHashAlgorithms[0].Hash)
	assert.Equal(t, signature.ECDSA, ext.SignatureHashAlgorithms[0].Signature)
	assert.Equal(t, hash.SHA384, ext.SignatureHashAlgorithms[1].Hash)
	assert.Equal(t, signature.ECDSA, ext.SignatureHashAlgorithms[1].Signature)
}

func TestSignatureAlgorithmsCertDuplicateAlgorithms(t *testing.T) {
	// Test handling of duplicate algorithms
	ext := &SignatureAlgorithmsCert{
		SignatureHashAlgorithms: []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.ECDSA},
			{Hash: hash.SHA256, Signature: signature.ECDSA}, // Duplicate
			{Hash: hash.SHA384, Signature: signature.ECDSA}, // Duplicate
		},
	}

	raw, err := ext.Marshal()
	assert.NoError(t, err)

	parsed := &SignatureAlgorithmsCert{}
	err = parsed.Unmarshal(raw)
	assert.NoError(t, err)

	// Should preserve duplicates (no deduplication in the protocol)
	assert.Len(t, parsed.SignatureHashAlgorithms, len(ext.SignatureHashAlgorithms))
}

func TestSignatureAlgorithmsCertLargeList(t *testing.T) {
	// Test with a large number of algorithms
	algorithms := make([]signaturehash.Algorithm, 0)
	for i := 0; i < 100; i++ {
		algorithms = append(algorithms, signaturehash.Algorithm{
			Hash:      hash.SHA256,
			Signature: signature.ECDSA,
		})
	}

	ext := &SignatureAlgorithmsCert{
		SignatureHashAlgorithms: algorithms,
	}

	raw, err := ext.Marshal()
	assert.NoError(t, err)

	parsed := &SignatureAlgorithmsCert{}
	err = parsed.Unmarshal(raw)
	assert.NoError(t, err)

	assert.Len(t, parsed.SignatureHashAlgorithms, len(ext.SignatureHashAlgorithms))
}

func FuzzSignatureAlgorithmsCertUnmarshal(f *testing.F) {
	testCases := [][]byte{
		// Basic valid extension with ECDSA algorithms
		{
			0x00, 0x32, // Extension type: signature_algorithms_cert (50)
			0x00, 0x08, // Extension length: 8 bytes
			0x00, 0x06, // Signature Hash Algorithms Length: 6 bytes
			0x04, 0x03, // SHA256, ECDSA
			0x05, 0x03, // SHA384, ECDSA
			0x06, 0x03, // SHA512, ECDSA
		},
		// PSS schemes (TLS 1.3 style)
		{
			0x00, 0x32, // Extension type
			0x00, 0x08, // Extension length
			0x00, 0x06, // Algorithms length
			0x08, 0x04, // RSA_PSS_RSAE_SHA256 (0x0804)
			0x08, 0x05, // RSA_PSS_RSAE_SHA384 (0x0805)
			0x08, 0x09, // RSA_PSS_PSS_SHA256 (0x0809)
		},
		// Mixed PSS and non-PSS with Ed25519 edge case
		{
			0x00, 0x32, // Extension type
			0x00, 0x0a, // Extension length
			0x00, 0x08, // Algorithms length
			0x08, 0x04, // RSA_PSS_RSAE_SHA256 (PSS)
			0x04, 0x01, // RSA PKCS#1 with SHA256
			0x04, 0x03, // ECDSA with SHA256
			0x08, 0x07, // Ed25519 (0x0807) - NOT PSS despite 0x08xx range
		},
		// Empty algorithm list
		{
			0x00, 0x32, // Extension type
			0x00, 0x02, // Extension length: 2 bytes
			0x00, 0x00, // Algorithms length: 0
		},
		// Single algorithm
		{
			0x00, 0x32, // Extension type
			0x00, 0x04, // Extension length: 4 bytes
			0x00, 0x02, // Algorithms length: 2 bytes
			0x04, 0x03, // SHA256, ECDSA
		},
		// Minimal malformed input
		{0x00},
		// Wrong extension type
		{0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03},
		// Truncated data
		{0x00, 0x32, 0x00, 0x06, 0x00, 0x04, 0x04},
	}
	for _, tc := range testCases {
		f.Add(tc)
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = (&SignatureAlgorithmsCert{}).Unmarshal(data)
	})
}
