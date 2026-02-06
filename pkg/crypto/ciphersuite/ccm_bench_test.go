//go:build bench

// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"testing"
)

// BenchmarkCCMEncrypt benchmarks CCM encryption with various payload sizes.
func BenchmarkCCMEncrypt(b *testing.B) {
	h := sha256.Sum256([]byte("benchmark-key"))
	localKey := h[:16]
	localWriteIV := h[16:20]

	ccmAEAD, err := NewCCM(CCMTagLength, localKey, localWriteIV, localKey, localWriteIV)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkEncrypt(b, ccmAEAD)
}

// BenchmarkCCMDecrypt benchmarks CCM decryption with various payload sizes.
func BenchmarkCCMDecrypt(b *testing.B) {
	h := sha256.Sum256([]byte("benchmark-key"))
	localKey := h[:16]
	localWriteIV := h[16:20]

	ccmAEAD, err := NewCCM(CCMTagLength, localKey, localWriteIV, localKey, localWriteIV)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkDecrypt(b, ccmAEAD)
}
