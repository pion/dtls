//go:build bench

// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"testing"
)

func newBenchmarkCBC() (testCipher, error) {
	key := sha256.Sum256([]byte("benchmark-key"))
	mac := sha256.Sum256([]byte("benchmark-mac"))

	return NewCBC(key[:16], key[16:], mac[:], key[:16], key[16:], mac[:], sha256.New)
}

func newBenchmarkCCM() (testCipher, error) {
	key := sha256.Sum256([]byte("benchmark-key"))

	return NewCCM(CCMTagLength, key[:16], key[16:20], key[:16], key[16:20])
}

func newBenchmarkChaCha20Poly1305() (testCipher, error) {
	key := sha256.Sum256([]byte("benchmark-key"))

	return newTestChaCha20Poly1305(&key, &key)
}

func newBenchmarkGCM() (testCipher, error) {
	key := sha256.Sum256([]byte("benchmark-key"))

	return newTestGCM(&key, &key)
}

// BenchmarkCBCEncrypt benchmarks CBC encryption with various payload sizes.
func BenchmarkCBCEncrypt(b *testing.B) {
	runCipherBenchmark(b, newBenchmarkCBC, benchmarkEncrypt)
}

// BenchmarkCBCDecrypt benchmarks CBC decryption with various payload sizes.
func BenchmarkCBCDecrypt(b *testing.B) {
	runCipherBenchmark(b, newBenchmarkCBC, benchmarkDecrypt)
}

// BenchmarkCCMEncrypt benchmarks CCM encryption with various payload sizes.
func BenchmarkCCMEncrypt(b *testing.B) {
	runCipherBenchmark(b, newBenchmarkCCM, benchmarkEncrypt)
}

// BenchmarkCCMDecrypt benchmarks CCM decryption with various payload sizes.
func BenchmarkCCMDecrypt(b *testing.B) {
	runCipherBenchmark(b, newBenchmarkCCM, benchmarkDecrypt)
}

// BenchmarkChaCha20Poly1305Encrypt benchmarks ChaCha20-Poly1305 encryption with various payload sizes.
func BenchmarkChaCha20Poly1305Encrypt(b *testing.B) {
	runCipherBenchmark(b, newBenchmarkChaCha20Poly1305, benchmarkEncrypt)
}

// BenchmarkChaCha20Poly1305Decrypt benchmarks ChaCha20-Poly1305 decryption with various payload sizes.
func BenchmarkChaCha20Poly1305Decrypt(b *testing.B) {
	runCipherBenchmark(b, newBenchmarkChaCha20Poly1305, benchmarkDecrypt)
}

// BenchmarkGCMEncrypt benchmarks GCM encryption with various payload sizes.
func BenchmarkGCMEncrypt(b *testing.B) {
	runCipherBenchmark(b, newBenchmarkGCM, benchmarkEncrypt)
}

// BenchmarkGCMDecrypt benchmarks GCM decryption with various payload sizes.
func BenchmarkGCMDecrypt(b *testing.B) {
	runCipherBenchmark(b, newBenchmarkGCM, benchmarkDecrypt)
}
