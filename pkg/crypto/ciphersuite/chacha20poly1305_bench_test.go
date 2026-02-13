//go:build bench

// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"testing"
)

// BenchmarkChaCha20Poly1305Encrypt benchmarks ChaCha20-Poly1305 encryption with various payload sizes.
func BenchmarkChaCha20Poly1305Encrypt(b *testing.B) {
	h := sha256.Sum256([]byte("benchmark-key"))
	localKey := h[:32] // ChaCha20 uses 32-byte keys
	localWriteIV := h[:12]

	chacha20poly1305AEAD, err := NewChaCha20Poly1305(localKey, localWriteIV, localKey, localWriteIV)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkEncrypt(b, chacha20poly1305AEAD)
}

// BenchmarkChaCha20Poly1305Decrypt benchmarks ChaCha20-Poly1305 decryption with various payload sizes.
func BenchmarkChaCha20Poly1305Decrypt(b *testing.B) {
	h := sha256.Sum256([]byte("benchmark-key"))
	localKey := h[:32] // ChaCha20 uses 32-byte keys
	localWriteIV := h[:12]

	chacha20poly1305AEAD, err := NewChaCha20Poly1305(localKey, localWriteIV, localKey, localWriteIV)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkDecrypt(b, chacha20poly1305AEAD)
}
