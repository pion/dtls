//go:build bench

// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"testing"
)

// BenchmarkCBCEncrypt benchmarks CBC encryption with various payload sizes.
func BenchmarkCBCEncrypt(b *testing.B) {
	h := sha256.Sum256([]byte("benchmark-key"))
	localKey := h[:16]
	localWriteIV := h[16:32] // IV must be 16 bytes for AES
	h2 := sha256.Sum256([]byte("benchmark-mac"))
	localMac := h2[:]

	cbcCipher, err := NewCBC(localKey, localWriteIV, localMac, localKey, localWriteIV, localMac, sha256.New)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkEncrypt(b, cbcCipher)
}

// BenchmarkCBCDecrypt benchmarks CBC decryption with various payload sizes.
func BenchmarkCBCDecrypt(b *testing.B) {
	h := sha256.Sum256([]byte("benchmark-key"))
	localKey := h[:16]
	localWriteIV := h[16:32] // IV must be 16 bytes for AES
	h2 := sha256.Sum256([]byte("benchmark-mac"))
	localMac := h2[:]

	cbcCipher, err := NewCBC(localKey, localWriteIV, localMac, localKey, localWriteIV, localMac, sha256.New)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkDecrypt(b, cbcCipher)
}
