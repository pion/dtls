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

func TestAlgorithms13_IncludesRSAPSS(t *testing.T) {
	algos := Algorithms13()

	// Verify DTLS 1.3 algorithms include RSA-PSS schemes
	hasRSAPSS := false
	for _, algo := range algos {
		if algo.Signature.IsPSS() {
			hasRSAPSS = true

			break
		}
	}
	assert.True(t, hasRSAPSS, "Algorithms13() should include RSA-PSS schemes")

	// Verify we still have RSA PKCS#1 v1.5 for backward compatibility
	hasRSA := false
	for _, algo := range algos {
		if algo.Signature == signature.RSA {
			hasRSA = true

			break
		}
	}
	assert.True(t, hasRSA, "Algorithms13() should include RSA PKCS#1 v1.5 for backward compatibility")
}

func TestAlgorithms13_RSAPSSBeforePKCS1(t *testing.T) {
	algos := Algorithms13()

	// Find positions of first RSA-PSS and first RSA PKCS#1 schemes
	firstRSAPSS := -1
	firstRSA := -1

	for i, algo := range algos {
		if firstRSAPSS == -1 && algo.Signature.IsPSS() {
			firstRSAPSS = i
		}
		if firstRSA == -1 && algo.Signature == signature.RSA {
			firstRSA = i
		}
	}

	// In TLS 1.3, RSA-PSS should be preferred over RSA PKCS#1 v1.5
	assert.NotEqual(t, -1, firstRSAPSS, "Should find RSA-PSS schemes")
	assert.NotEqual(t, -1, firstRSA, "Should find RSA PKCS#1 schemes")
	assert.Less(t, firstRSAPSS, firstRSA,
		"RSA-PSS schemes should come before RSA PKCS#1 in Algorithms13() for TLS 1.3 preference")
}
