// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/require"
)

func FuzzChaCha20Poly1305_RoundTrip(f *testing.F) {
	f.Add([]byte{}, []byte("x"), uint64(0), uint16(0))
	f.Add([]byte{7, 8, 9}, []byte("alpha"), uint64(5), uint16(1))
	f.Add(make([]byte, 2048), []byte("left"), uint64(0x0a0b0c0d0e0f), uint16(3))

	f.Fuzz(func(t *testing.T, plain []byte, seed []byte, seq uint64, epoch uint16) {
		if len(plain) > 1<<14 {
			plain = plain[:1<<14]
		}

		h := sha256.Sum256(seed)
		localKey := h[:32] // ChaCha20 uses 32-byte keys
		localWriteIV := h[:12]

		chachaAEAD, err := NewChaCha20Poly1305(localKey, localWriteIV, localKey, localWriteIV)
		require.NoError(t, err)

		hdr := recordlayer.Header{
			ContentType:    protocol.ContentTypeApplicationData,
			Version:        protocol.Version1_2,
			Epoch:          epoch,
			SequenceNumber: seq,
		}

		headerRaw, err := hdr.Marshal()
		require.NoError(t, err)

		raw := make([]byte, len(headerRaw)+len(plain))
		copy(raw, headerRaw)
		copy(raw[len(headerRaw):], plain)

		enc, err := chachaAEAD.Encrypt(&recordlayer.RecordLayer{Header: hdr}, raw)
		require.NoError(t, err)

		dec, err := chachaAEAD.Decrypt(recordlayer.Header{}, enc)
		require.NoError(t, err)

		var parsedHdr recordlayer.Header
		require.NoError(t, parsedHdr.Unmarshal(dec))
		got := dec[parsedHdr.Size():]

		require.Equal(t, plain, got)
	})
}

func FuzzChaCha20Poly1305_Bidirectional_RoundTrip(f *testing.F) {
	f.Add([]byte("hello"), []byte("seedA"), uint64(1), uint16(0),
		[]byte("world"), []byte("seedB"), uint64(2), uint16(1))

	f.Add([]byte{}, []byte("zero"), uint64(0), uint16(0),
		[]byte{1, 2, 3, 4}, []byte("other"), uint64(5), uint16(2))

	f.Add(make([]byte, 2048), []byte("AAA"), uint64(123456), uint16(3),
		make([]byte, 17), []byte("BBB"), uint64(789), uint16(4))

	f.Fuzz(func(t *testing.T,
		pA []byte, sA []byte, seqA uint64, epochA uint16,
		pB []byte, sB []byte, seqB uint64, epochB uint16,
	) {
		if len(pA) > 1<<14 {
			pA = pA[:1<<14]
		}

		if len(pB) > 1<<14 {
			pB = pB[:1<<14]
		}

		hA := sha256.Sum256(sA)
		hB := sha256.Sum256(sB)
		localKeyA, localWriteIVA := hA[:32], hA[:12] // ChaCha20 uses 32-byte keys
		localKeyB, localWriteIVB := hB[:32], hB[:12]

		// A uses (keyA,ivA) to send and expects (keyB, ivB) for receive.
		chachaA, err := NewChaCha20Poly1305(localKeyA, localWriteIVA, localKeyB, localWriteIVB)
		require.NoError(t, err)

		// B uses (keyB,ivB) to send and expects (keyA, ivA) for receive.
		chachaB, err := NewChaCha20Poly1305(localKeyB, localWriteIVB, localKeyA, localWriteIVA)
		require.NoError(t, err)

		// A -> B
		hdrA := recordlayer.Header{
			ContentType:    protocol.ContentTypeApplicationData,
			Version:        protocol.Version1_2,
			Epoch:          epochA,
			SequenceNumber: seqA,
		}

		headerRawA, err := hdrA.Marshal()
		require.NoError(t, err)

		rawA := make([]byte, len(headerRawA)+len(pA))
		copy(rawA, headerRawA)
		copy(rawA[len(headerRawA):], pA)

		encA, err := chachaA.Encrypt(&recordlayer.RecordLayer{Header: hdrA}, rawA)
		require.NoError(t, err)

		decAonB, err := chachaB.Decrypt(recordlayer.Header{}, encA)
		require.NoError(t, err)

		// parse header from decrypted bytes to compute payload offset safely.
		var parsedHdrA recordlayer.Header
		require.NoError(t, parsedHdrA.Unmarshal(decAonB))

		gotA := decAonB[parsedHdrA.Size():]
		require.Equal(t, pA, gotA)

		// B -> A
		hdrB := recordlayer.Header{
			ContentType:    protocol.ContentTypeApplicationData,
			Version:        protocol.Version1_2,
			Epoch:          epochB,
			SequenceNumber: seqB,
		}

		headerRawB, err := hdrB.Marshal()
		require.NoError(t, err)

		rawB := make([]byte, len(headerRawB)+len(pB))
		copy(rawB, headerRawB)
		copy(rawB[len(headerRawB):], pB)

		encB, err := chachaB.Encrypt(&recordlayer.RecordLayer{Header: hdrB}, rawB)
		require.NoError(t, err)

		decBonA, err := chachaA.Decrypt(recordlayer.Header{}, encB)
		require.NoError(t, err)

		var parsedHdrB recordlayer.Header
		require.NoError(t, parsedHdrB.Unmarshal(decBonA))

		gotB := decBonA[parsedHdrB.Size():]
		require.Equal(t, pB, gotB)
	})
}
