// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/require"
)

type testRecord uint64

func newTestRecord(epoch uint16, sequence uint64) testRecord {
	return testRecord(uint64(epoch)<<48 | sequence)
}

func (r testRecord) RecordNumber() uint64 { return uint64(r) }

func (r testRecord) AuthenticationData(recordLen int) ([]byte, error) {
	if recordLen < 0 || recordLen > math.MaxUint16 {
		return nil, cryptosuite.ErrInvalidCapabilities
	}

	var additionalData [13]byte
	binary.BigEndian.PutUint64(additionalData[:], uint64(r))
	additionalData[8] = byte(protocol.ContentTypeApplicationData)
	additionalData[9] = protocol.Version1_2.Major()
	additionalData[10] = protocol.Version1_2.Minor()
	binary.BigEndian.PutUint16(additionalData[11:], uint16(recordLen)) //nolint:gosec // Bounded above.

	return additionalData[:], nil
}

type fuzzSeedHash = [sha256.Size]byte

type fuzzProtectionFactory func(localHash, remoteHash *fuzzSeedHash) (cryptosuite.Protection, error)

func newTestGCM(localHash, remoteHash *fuzzSeedHash) (cryptosuite.Protection, error) {
	return newGCM(localHash[:16], localHash[16:20], remoteHash[:16], remoteHash[16:20])
}

func newTestChaCha20Poly1305(localHash, remoteHash *fuzzSeedHash) (cryptosuite.Protection, error) {
	return newChaCha20Poly1305(localHash[:], localHash[:12], remoteHash[:], remoteHash[:12])
}

func FuzzGCM_RoundTrip(f *testing.F) {
	fuzzProtectionRoundTrip(f, newTestGCM)
}

func FuzzGCM_Bidirectional_RoundTrip(f *testing.F) {
	fuzzProtectionBidirectionalRoundTrip(f, newTestGCM)
}

func FuzzChaCha20Poly1305_RoundTrip(f *testing.F) {
	fuzzProtectionRoundTrip(f, newTestChaCha20Poly1305)
}

func FuzzChaCha20Poly1305_Bidirectional_RoundTrip(f *testing.F) {
	fuzzProtectionBidirectionalRoundTrip(f, newTestChaCha20Poly1305)
}

func fuzzProtectionRoundTrip(f *testing.F, newProtection fuzzProtectionFactory) {
	f.Helper()

	f.Add([]byte{}, []byte("x"), uint64(0), uint16(0))
	f.Add([]byte{7, 8, 9}, []byte("alpha"), uint64(5), uint16(1))
	f.Add(make([]byte, 2048), []byte("left"), uint64(0x0a0b0c0d0e0f), uint16(3))

	f.Fuzz(func(t *testing.T, plaintext, seed []byte, sequenceNumber uint64, epoch uint16) {
		plaintext = plaintext[:min(len(plaintext), 1<<14)]
		seedHash := sha256.Sum256(seed)
		protection, err := newProtection(&seedHash, &seedHash)
		require.NoError(t, err)

		assertProtectionRoundTrip(t, protection, protection, plaintext, sequenceNumber, epoch)
	})
}

func fuzzProtectionBidirectionalRoundTrip(f *testing.F, newProtection fuzzProtectionFactory) {
	f.Helper()

	f.Add([]byte("hello"), []byte("seedA"), uint64(1), uint16(0),
		[]byte("world"), []byte("seedB"), uint64(2), uint16(1))
	f.Add([]byte{}, []byte("zero"), uint64(0), uint16(0),
		[]byte{1, 2, 3, 4}, []byte("other"), uint64(5), uint16(2))
	f.Add(make([]byte, 2048), []byte("AAA"), uint64(123456), uint16(3), make([]byte, 17), []byte("BBB"), uint64(789), uint16(4))

	f.Fuzz(func(t *testing.T,
		plaintextA, seedA []byte, sequenceNumberA uint64, epochA uint16,
		plaintextB, seedB []byte, sequenceNumberB uint64, epochB uint16,
	) {
		plaintextA = plaintextA[:min(len(plaintextA), 1<<14)]
		plaintextB = plaintextB[:min(len(plaintextB), 1<<14)]
		seedHashA := sha256.Sum256(seedA)
		seedHashB := sha256.Sum256(seedB)

		protectionA, err := newProtection(&seedHashA, &seedHashB)
		require.NoError(t, err)
		protectionB, err := newProtection(&seedHashB, &seedHashA)
		require.NoError(t, err)

		assertProtectionRoundTrip(t, protectionA, protectionB, plaintextA, sequenceNumberA, epochA)
		assertProtectionRoundTrip(t, protectionB, protectionA, plaintextB, sequenceNumberB, epochB)
	})
}

func assertProtectionRoundTrip(t *testing.T, sender, receiver cryptosuite.Protection, plaintext []byte, sequenceNumber uint64, epoch uint16) {
	t.Helper()
	sequenceNumber &= recordlayer.MaxSequenceNumber

	record := newTestRecord(epoch, sequenceNumber)
	plaintextBefore := bytes.Clone(plaintext)
	protected, err := sender.Seal(record, plaintext)
	require.NoError(t, err)
	require.Equal(t, plaintextBefore, plaintext)
	protectedBefore := bytes.Clone(protected)
	opened, err := receiver.Open(record, protected)
	require.NoError(t, err)
	require.True(t, bytes.Equal(plaintext, opened))
	require.Equal(t, protectedBefore, protected)
}

func FuzzCCM_RoundTrip(f *testing.F) {
	f.Add(byte(8), []byte{1, 2, 3, 4, 5}, uint16(0), uint64(0))
	f.Add(byte(16), []byte{}, uint16(1), uint64(7))
	f.Add(byte(8), make([]byte, 64), uint16(3), uint64(42))

	f.Fuzz(func(t *testing.T, tagLenByte byte, payload []byte, epoch uint16, sequenceNumber uint64) {
		payload = payload[:min(len(payload), 1<<14)]
		sequenceNumber &= recordlayer.MaxSequenceNumber
		tagLen := ccmTagLength8
		if tagLenByte%2 == 0 {
			tagLen = ccmTagLength
		}

		key := make([]byte, 16)
		for i := range key {
			if i < len(payload) {
				key[i] = payload[i]
			} else {
				key[i] = byte(i*31 + 7)
			}
		}

		var encodedSequence [8]byte
		binary.BigEndian.PutUint64(encodedSequence[:], sequenceNumber^0xA5A5A5A5A5A5A5A5)
		iv := bytes.Clone(encodedSequence[4:])

		protection, err := newCCM(tagLen, key, iv, key, iv)
		require.NoError(t, err)
		assertProtectionRoundTrip(t, protection, protection, payload, sequenceNumber, epoch)
	})
}

func FuzzCCM_Open(f *testing.F) {
	f.Add([]byte{1, 2, 3})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, protected []byte) {
		protected = protected[:min(len(protected), 1<<15)]
		key := make([]byte, 16)
		protection, err := newCCM(ccmTagLength8, key, []byte{0, 0, 0, 0}, key, []byte{0, 0, 0, 0})
		require.NoError(t, err)

		before := bytes.Clone(protected)
		_, err = protection.Open(newTestRecord(0, 0), protected)
		require.True(t, err == nil || errors.Is(err, cryptosuite.ErrAuthenticationFailed))
		require.Equal(t, before, protected)
	})
}
