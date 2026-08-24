// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package signaturehash

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/stretchr/testify/assert"
)

func TestAlgorithms13(t *testing.T) {
	algos := Algorithms13()

	// Verify we got expected number of algorithms
	// ECDSA (3) + Ed25519 (1) + RSA-PSS (3) + RSA PKCS#1 (3) = 10
	assert.Len(t, algos, 10, "Algorithms13 should return 10 signature schemes")

	// Verify ECDSA schemes come first (industry standard preference)
	assert.Equal(t, Algorithm{hash.SHA256, signature.ECDSA}, algos[0])
	assert.Equal(t, Algorithm{hash.SHA384, signature.ECDSA}, algos[1])
	assert.Equal(t, Algorithm{hash.SHA512, signature.ECDSA}, algos[2])

	// Verify Ed25519
	assert.Equal(t, Algorithm{hash.Ed25519, signature.Ed25519}, algos[3])

	// Verify RSA-PSS schemes (TLS 1.3 preference for RSA)
	assert.Equal(t, Algorithm{hash.SHA256, signature.RSA_PSS_RSAE_SHA256}, algos[4])
	assert.Equal(t, Algorithm{hash.SHA384, signature.RSA_PSS_RSAE_SHA384}, algos[5])
	assert.Equal(t, Algorithm{hash.SHA512, signature.RSA_PSS_RSAE_SHA512}, algos[6])

	// Verify RSA PKCS#1 v1.5 schemes come last (TLS 1.2 compatibility)
	assert.Equal(t, Algorithm{hash.SHA256, signature.RSA}, algos[7])
	assert.Equal(t, Algorithm{hash.SHA384, signature.RSA}, algos[8])
	assert.Equal(t, Algorithm{hash.SHA512, signature.RSA}, algos[9])
}
