// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package hash

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/fingerprint"
	"github.com/stretchr/testify/assert"
)

func TestHashAlgorithm_StringRoundtrip(t *testing.T) {
	for algo := range Algorithms() {
		if algo == Ed25519 || algo == None {
			continue
		}

		str := algo.String()
		hash1 := algo.CryptoHash()
		hash2, err := fingerprint.HashFromString(str)
		assert.NoError(t, err)
		assert.Equal(t, hash1, hash2)
	}
}

func TestExtractHashFromPSS(t *testing.T) {
	tests := []struct {
		name     string
		scheme   uint16
		expected Algorithm
	}{
		// RSA-PSS-RSAE schemes
		{"RSA_PSS_RSAE_SHA256", 0x0804, SHA256},
		{"RSA_PSS_RSAE_SHA384", 0x0805, SHA384},
		{"RSA_PSS_RSAE_SHA512", 0x0806, SHA512},
		// RSA-PSS-PSS schemes
		{"RSA_PSS_PSS_SHA256", 0x0809, SHA256},
		{"RSA_PSS_PSS_SHA384", 0x080a, SHA384},
		{"RSA_PSS_PSS_SHA512", 0x080b, SHA512},
		// Non-PSS schemes should return None
		{"Ed25519", 0x0807, None},
		{"Ed448", 0x0808, None},
		{"ECDSA_SHA256", 0x0403, None},
		{"RSA_PKCS1_SHA256", 0x0401, None},
		{"Unknown", 0xFFFF, None},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractHashFromPSS(tt.scheme)
			assert.Equal(t, tt.expected, result)
		})
	}
}
