// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/stretchr/testify/assert"
)

func TestExtensionSupportedSignatureAlgorithms(t *testing.T) {
	rawExtensionSupportedSignatureAlgorithms := []byte{
		0x00, 0x0d,
		0x00, 0x08,
		0x00, 0x06,
		0x04, 0x03,
		0x05, 0x03,
		0x06, 0x03,
	}
	parsedExtensionSupportedSignatureAlgorithms := &SupportedSignatureAlgorithms{
		SignatureHashAlgorithms: []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.ECDSA},
			{Hash: hash.SHA384, Signature: signature.ECDSA},
			{Hash: hash.SHA512, Signature: signature.ECDSA},
		},
	}

	raw, err := parsedExtensionSupportedSignatureAlgorithms.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawExtensionSupportedSignatureAlgorithms, raw)

	roundtrip := &SupportedSignatureAlgorithms{}
	assert.NoError(t, roundtrip.Unmarshal(raw))
	assert.Equal(t, parsedExtensionSupportedSignatureAlgorithms, roundtrip)
}

func TestExtensionSupportedSignatureAlgorithms_PSSSchemes(t *testing.T) {
	// Test PSS schemes using full uint16 encoding (TLS 1.3 style)
	rawExtensionWithPSS := []byte{
		0x00, 0x0d, // Extension type
		0x00, 0x08, // Extension length (8 bytes)
		0x00, 0x06, // Algorithms length (6 bytes = 3 schemes)
		0x08, 0x04, // RSA_PSS_RSAE_SHA256 (0x0804)
		0x08, 0x05, // RSA_PSS_RSAE_SHA384 (0x0805)
		0x08, 0x09, // RSA_PSS_PSS_SHA256 (0x0809)
	}
	parsedExtensionWithPSS := &SupportedSignatureAlgorithms{
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
	roundtrip := &SupportedSignatureAlgorithms{}
	assert.NoError(t, roundtrip.Unmarshal(raw))
	assert.Equal(t, parsedExtensionWithPSS, roundtrip)
}

func TestExtensionSupportedSignatureAlgorithms_MixedPSSAndNonPSS(t *testing.T) {
	// Test mixed PSS and non-PSS schemes
	rawExtensionMixed := []byte{
		0x00, 0x0d, // Extension type
		0x00, 0x0a, // Extension length (10 bytes)
		0x00, 0x08, // Algorithms length (8 bytes = 4 schemes)
		0x08, 0x04, // RSA_PSS_RSAE_SHA256 (0x0804) - PSS
		0x04, 0x01, // RSA PKCS#1 with SHA256 - Non-PSS
		0x04, 0x03, // ECDSA with SHA256 - Non-PSS
		0x08, 0x07, // Ed25519 (0x0807) - Not PSS despite being in 0x08xx range
	}
	parsedExtensionMixed := &SupportedSignatureAlgorithms{
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
	roundtrip := &SupportedSignatureAlgorithms{}
	assert.NoError(t, roundtrip.Unmarshal(raw))
	assert.Equal(t, parsedExtensionMixed, roundtrip)
}
