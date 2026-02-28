//go:build bench

// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"testing"
)

// BenchmarkGCMEncrypt benchmarks GCM encryption with various payload sizes.
func BenchmarkGCMEncrypt(b *testing.B) {
	h := sha256.Sum256([]byte("benchmark-key"))
	localKey := h[:16]
	localWriteIV := h[16:20]

	gcmAEAD, err := NewGCM(localKey, localWriteIV, localKey, localWriteIV)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkEncrypt(b, gcmAEAD)
}

// BenchmarkGCMDecrypt benchmarks GCM decryption with various payload sizes.
func BenchmarkGCMDecrypt(b *testing.B) {
	h := sha256.Sum256([]byte("benchmark-key"))
	localKey := h[:16]
	localWriteIV := h[16:20]

	gcmAEAD, err := NewGCM(localKey, localWriteIV, localKey, localWriteIV)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkDecrypt(b, gcmAEAD)
}
