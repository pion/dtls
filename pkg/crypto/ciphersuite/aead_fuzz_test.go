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

type testCipher interface {
	Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error)
	Decrypt(header recordlayer.Header, in []byte) ([]byte, error)
}

type fuzzSeedHash = [sha256.Size]byte

type fuzzCipherFactory func(localHash, remoteHash *fuzzSeedHash) (testCipher, error)

func newTestGCM(localHash, remoteHash *fuzzSeedHash) (testCipher, error) {
	return NewGCM(localHash[:16], localHash[16:20], remoteHash[:16], remoteHash[16:20])
}

func newTestChaCha20Poly1305(localHash, remoteHash *fuzzSeedHash) (testCipher, error) {
	return NewChaCha20Poly1305(localHash[:], localHash[:12], remoteHash[:], remoteHash[:12])
}

func FuzzGCM_RoundTrip(f *testing.F) {
	fuzzCipherRoundTrip(f, newTestGCM)
}

func FuzzGCM_Bidirectional_RoundTrip(f *testing.F) {
	fuzzCipherBidirectionalRoundTrip(f, newTestGCM)
}

func FuzzChaCha20Poly1305_RoundTrip(f *testing.F) {
	fuzzCipherRoundTrip(f, newTestChaCha20Poly1305)
}

func FuzzChaCha20Poly1305_Bidirectional_RoundTrip(f *testing.F) {
	fuzzCipherBidirectionalRoundTrip(f, newTestChaCha20Poly1305)
}

func fuzzCipherRoundTrip(f *testing.F, newCipher fuzzCipherFactory) {
	f.Helper()

	f.Add([]byte{}, []byte("x"), uint64(0), uint16(0))
	f.Add([]byte{7, 8, 9}, []byte("alpha"), uint64(5), uint16(1))
	f.Add(make([]byte, 2048), []byte("left"), uint64(0x0a0b0c0d0e0f), uint16(3))

	f.Fuzz(func(t *testing.T, plaintext, seed []byte, sequenceNumber uint64, epoch uint16) {
		plaintext = plaintext[:min(len(plaintext), 1<<14)]
		seedHash := sha256.Sum256(seed)
		cipher, err := newCipher(&seedHash, &seedHash)
		require.NoError(t, err)

		assertFuzzCipherRoundTrip(t, cipher, cipher, plaintext, sequenceNumber, epoch)
	})
}

func fuzzCipherBidirectionalRoundTrip(f *testing.F, newCipher fuzzCipherFactory) {
	f.Helper()

	f.Add([]byte("hello"), []byte("seedA"), uint64(1), uint16(0),
		[]byte("world"), []byte("seedB"), uint64(2), uint16(1))
	f.Add([]byte{}, []byte("zero"), uint64(0), uint16(0),
		[]byte{1, 2, 3, 4}, []byte("other"), uint64(5), uint16(2))
	f.Add(make([]byte, 2048), []byte("AAA"), uint64(123456), uint16(3),
		make([]byte, 17), []byte("BBB"), uint64(789), uint16(4))

	f.Fuzz(func(t *testing.T,
		plaintextA, seedA []byte, sequenceNumberA uint64, epochA uint16,
		plaintextB, seedB []byte, sequenceNumberB uint64, epochB uint16,
	) {
		plaintextA = plaintextA[:min(len(plaintextA), 1<<14)]
		plaintextB = plaintextB[:min(len(plaintextB), 1<<14)]
		seedHashA := sha256.Sum256(seedA)
		seedHashB := sha256.Sum256(seedB)

		cipherA, err := newCipher(&seedHashA, &seedHashB)
		require.NoError(t, err)
		cipherB, err := newCipher(&seedHashB, &seedHashA)
		require.NoError(t, err)

		assertFuzzCipherRoundTrip(t, cipherA, cipherB, plaintextA, sequenceNumberA, epochA)
		assertFuzzCipherRoundTrip(t, cipherB, cipherA, plaintextB, sequenceNumberB, epochB)
	})
}

func assertFuzzCipherRoundTrip(
	t *testing.T,
	sender, receiver testCipher,
	plaintext []byte,
	sequenceNumber uint64,
	epoch uint16,
) {
	t.Helper()

	header := recordlayer.Header{
		ContentType:    protocol.ContentTypeApplicationData,
		Version:        protocol.Version1_2,
		Epoch:          epoch,
		SequenceNumber: sequenceNumber,
	}
	headerRaw, err := header.Marshal()
	require.NoError(t, err)
	raw := make([]byte, len(headerRaw)+len(plaintext))
	copy(raw, headerRaw)
	copy(raw[len(headerRaw):], plaintext)

	encrypted, err := sender.Encrypt(&recordlayer.RecordLayer{Header: header}, raw)
	require.NoError(t, err)
	decrypted, err := receiver.Decrypt(recordlayer.Header{}, encrypted)
	require.NoError(t, err)

	var parsedHeader recordlayer.Header
	require.NoError(t, parsedHeader.Unmarshal(decrypted))
	require.Equal(t, plaintext, decrypted[parsedHeader.Size():])
}
