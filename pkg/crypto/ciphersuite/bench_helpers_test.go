//go:build bench

// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

type testCipher interface {
	Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error)
	Decrypt(header recordlayer.Header, in []byte) ([]byte, error)
}

// benchmarkEncrypt benchmarks a cipher's encryption with various payload sizes.
func benchmarkEncrypt(b *testing.B, cipher testCipher) {
	b.Helper()

	payloadSizes := []int{16, 64, 128, 256, 512, 800, 1024, 1200, 1500, 4096, 8192}

	for _, size := range payloadSizes {
		b.Run(formatSize(b, size), func(b *testing.B) {
			hdr := recordlayer.Header{
				ContentType:    protocol.ContentTypeApplicationData,
				Version:        protocol.Version1_2,
				Epoch:          1,
				SequenceNumber: 12345,
			}

			headerRaw, err := hdr.Marshal()
			if err != nil {
				b.Fatal(err)
			}

			payload := make([]byte, size)
			raw := make([]byte, len(headerRaw)+len(payload))
			copy(raw, headerRaw)
			copy(raw[len(headerRaw):], payload)

			pkt := &recordlayer.RecordLayer{Header: hdr}

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				rawCopy := make([]byte, len(raw))
				copy(rawCopy, raw)

				_, err := cipher.Encrypt(pkt, rawCopy)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// benchmarkDecrypt benchmarks a cipher's decryption with various payload sizes.
func benchmarkDecrypt(b *testing.B, cipher testCipher) {
	b.Helper()

	payloadSizes := []int{16, 64, 256, 512, 1024, 1500}

	for _, size := range payloadSizes {
		b.Run(formatSize(b, size), func(b *testing.B) {
			hdr := recordlayer.Header{
				ContentType:    protocol.ContentTypeApplicationData,
				Version:        protocol.Version1_2,
				Epoch:          1,
				SequenceNumber: 12345,
			}

			headerRaw, err := hdr.Marshal()
			if err != nil {
				b.Fatal(err)
			}

			payload := make([]byte, size)
			raw := make([]byte, len(headerRaw)+len(payload))
			copy(raw, headerRaw)
			copy(raw[len(headerRaw):], payload)

			pkt := &recordlayer.RecordLayer{Header: hdr}
			encrypted, err := cipher.Encrypt(pkt, raw)
			if err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				encCopy := make([]byte, len(encrypted))
				copy(encCopy, encrypted)

				_, err := cipher.Decrypt(hdr, encCopy)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func formatSize(b *testing.B, size int) string {
	b.Helper()

	if size < 1024 {
		return string(rune('0'+size/100)) + string(rune('0'+(size/10)%10)) + string(rune('0'+size%10)) + "B"
	} else if size < 10240 {
		kb := size / 1024
		remainder := (size % 1024) * 10 / 1024
		if remainder > 0 {
			return string(rune('0'+kb)) + "." + string(rune('0'+remainder)) + "KB"
		}

		return string(rune('0'+kb)) + "KB"
	}

	return string(rune('0'+size/1024/10)) + string(rune('0'+(size/1024)%10)) + "KB"
}
