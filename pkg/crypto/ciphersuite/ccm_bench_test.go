//go:build bench

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
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

	payloadSizes := []int{16, 64, 256, 512, 1024, 1500}

	// nolint:dupl
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

				_, err := ccmAEAD.Encrypt(pkt, rawCopy)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
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

	payloadSizes := []int{16, 64, 256, 512, 1024, 1500}

	// nolint:dupl
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
			encrypted, err := ccmAEAD.Encrypt(pkt, raw)
			if err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				encCopy := make([]byte, len(encrypted))
				copy(encCopy, encrypted)

				_, err := ccmAEAD.Decrypt(hdr, encCopy)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
