// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package signature

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/stretchr/testify/assert"
)

func TestIsPSS(t *testing.T) {
	tests := []struct {
		name     string
		alg      Algorithm
		expected bool
	}{
		{"RSA_PSS_RSAE_SHA256", RSA_PSS_RSAE_SHA256, true},
		{"RSA_PSS_RSAE_SHA384", RSA_PSS_RSAE_SHA384, true},
		{"RSA_PSS_RSAE_SHA512", RSA_PSS_RSAE_SHA512, true},
		{"RSA_PSS_PSS_SHA256", RSA_PSS_PSS_SHA256, true},
		{"RSA_PSS_PSS_SHA384", RSA_PSS_PSS_SHA384, true},
		{"RSA_PSS_PSS_SHA512", RSA_PSS_PSS_SHA512, true},
		{"RSA", RSA, false},
		{"ECDSA", ECDSA, false},
		{"Ed25519", Ed25519, false},
		{"Anonymous", Anonymous, false},
		// Edge cases: 0x0807 (Ed25519) and 0x0808 (Ed448) fall within the 0x0804-0x080b range
		// but are NOT PSS schemes. This test ensures we check specific values, not just ranges.
		{"0x0807_Ed25519_raw", Algorithm(0x0807), false},
		{"0x0808_Ed448_raw", Algorithm(0x0808), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.alg.IsPSS()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsUnsupported(t *testing.T) {
	tests := []struct {
		name     string
		alg      Algorithm
		expected bool
	}{
		{"RSA_PSS_RSAE_SHA256", RSA_PSS_RSAE_SHA256, false},
		{"RSA_PSS_RSAE_SHA384", RSA_PSS_RSAE_SHA384, false},
		{"RSA_PSS_RSAE_SHA512", RSA_PSS_RSAE_SHA512, false},
		{"RSA_PSS_PSS_SHA256", RSA_PSS_PSS_SHA256, true},
		{"RSA_PSS_PSS_SHA384", RSA_PSS_PSS_SHA384, true},
		{"RSA_PSS_PSS_SHA512", RSA_PSS_PSS_SHA512, true},
		{"RSA", RSA, false},
		{"ECDSA", ECDSA, false},
		{"Ed25519", Ed25519, false},
		{"Anonymous", Anonymous, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.alg.IsUnsupported()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetPSSHash(t *testing.T) {
	tests := []struct {
		name     string
		alg      Algorithm
		expected hash.Algorithm
	}{
		{"RSA_PSS_RSAE_SHA256", RSA_PSS_RSAE_SHA256, hash.SHA256},
		{"RSA_PSS_RSAE_SHA384", RSA_PSS_RSAE_SHA384, hash.SHA384},
		{"RSA_PSS_RSAE_SHA512", RSA_PSS_RSAE_SHA512, hash.SHA512},
		{"RSA_PSS_PSS_SHA256", RSA_PSS_PSS_SHA256, hash.SHA256},
		{"RSA_PSS_PSS_SHA384", RSA_PSS_PSS_SHA384, hash.SHA384},
		{"RSA_PSS_PSS_SHA512", RSA_PSS_PSS_SHA512, hash.SHA512},
		{"RSA", RSA, hash.None},
		{"ECDSA", ECDSA, hash.None},
		{"Ed25519", Ed25519, hash.None},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.alg.GetPSSHash()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAlgorithms(t *testing.T) {
	algs := Algorithms()

	// Verify all PSS algorithms are included
	assert.Contains(t, algs, RSA_PSS_RSAE_SHA256)
	assert.Contains(t, algs, RSA_PSS_RSAE_SHA384)
	assert.Contains(t, algs, RSA_PSS_RSAE_SHA512)
	assert.Contains(t, algs, RSA_PSS_PSS_SHA256)
	assert.Contains(t, algs, RSA_PSS_PSS_SHA384)
	assert.Contains(t, algs, RSA_PSS_PSS_SHA512)

	// Verify legacy algorithms are still included
	assert.Contains(t, algs, RSA)
	assert.Contains(t, algs, ECDSA)
	assert.Contains(t, algs, Ed25519)
	assert.Contains(t, algs, Anonymous)
}
