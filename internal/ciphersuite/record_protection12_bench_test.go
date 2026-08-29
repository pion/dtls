//go:build bench

// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"fmt"
	"testing"

	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
)

type benchmarkProtectionFactory func() (cryptosuite.Protection, error)

func BenchmarkRecordProtection12(b *testing.B) {
	key := sha256.Sum256([]byte("benchmark-key"))
	mac := sha256.Sum256([]byte("benchmark-mac"))
	algorithms := []struct {
		name string
		new  benchmarkProtectionFactory
	}{
		{"CBC", func() (cryptosuite.Protection, error) {
			return newCBC(key[:16], key[16:], mac[:], key[:16], key[16:], mac[:], sha256.New)
		}},
		{"CCM", func() (cryptosuite.Protection, error) {
			return newCCM(ccmTagLength, key[:16], key[16:20], key[:16], key[16:20])
		}},
		{"ChaCha20Poly1305", func() (cryptosuite.Protection, error) {
			return newTestChaCha20Poly1305(&key, &key)
		}},
		{"GCM", func() (cryptosuite.Protection, error) {
			return newTestGCM(&key, &key)
		}},
	}

	for _, algorithm := range algorithms {
		b.Run(algorithm.name, func(b *testing.B) {
			protection, err := algorithm.new()
			if err != nil {
				b.Fatal(err)
			}
			b.Run("Seal", func(b *testing.B) { benchmarkSeal(b, protection) })
			b.Run("Open", func(b *testing.B) { benchmarkOpen(b, protection) })
		})
	}
}

func benchmarkSeal(b *testing.B, protection cryptosuite.Protection) {
	b.Helper()

	for _, size := range []int{16, 64, 128, 256, 512, 800, 1024, 1200, 1500, 4096, 8192} {
		b.Run(formatSize(size), func(b *testing.B) {
			record := newTestRecord(1, 12345)
			payload := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))

			for b.Loop() {
				if _, err := protection.Seal(record, payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkOpen(b *testing.B, protection cryptosuite.Protection) {
	b.Helper()

	for _, size := range []int{16, 64, 256, 512, 1024, 1500} {
		b.Run(formatSize(size), func(b *testing.B) {
			record := newTestRecord(1, 12345)
			protected, err := protection.Seal(record, make([]byte, size))
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(size))

			for b.Loop() {
				if _, err := protection.Open(record, protected); err != nil {
					b.Fatalf("open failed: %v", err)
				}
			}
		})
	}
}

func formatSize(size int) string {
	if size < 1024 {
		return fmt.Sprintf("%dB", size)
	}
	if size%1024 == 0 {
		return fmt.Sprintf("%dKB", size/1024)
	}

	return fmt.Sprintf("%.1fKB", float64(size)/1024)
}
