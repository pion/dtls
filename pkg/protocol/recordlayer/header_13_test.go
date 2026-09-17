// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnifiedRecordWireChoices(t *testing.T) {
	for _, cid := range [][]byte{nil, {0xca, 0xfe}} {
		for _, two := range []bool{false, true} {
			for _, length := range []bool{false, true} {
				config := CiphertextConfig{EpochLow: 3, SequenceNumber: 0x42, ConnectionID: cid, TwoByteSequence: two, LengthPresent: length}
				want := byte(0x23)
				if len(cid) > 0 {
					want |= 0x10
				}
				if two {
					want |= 0x08
					config.SequenceNumber = 0xaabb
				}
				if length {
					want |= 0x04
				}
				header := append([]byte{want}, cid...)
				if two {
					header = append(header, 0xaa, 0xbb)
				} else {
					header = append(header, 0x42)
				}
				if length {
					header = append(header, 0, 16)
				}
				ciphertext := bytes.Repeat([]byte{0xde}, 16)
				raw, err := MarshalCiphertext(config, ciphertext)
				require.NoError(t, err)
				require.Equal(t, append(bytes.Clone(header), ciphertext...), raw)
				parsed, err := ParseRecord(raw, len(cid))
				require.NoError(t, err)
				require.True(t, parsed.IsUnified())
				require.Zero(t, parsed.ContentType())
				require.Zero(t, parsed.Version())
				require.Zero(t, parsed.Epoch())
				require.Equal(t, config.EpochLow, parsed.EpochLow())
				require.Equal(t, uint64(config.SequenceNumber), parsed.SequenceNumber())
				require.Equal(t, two, parsed.SequenceBytes() == 2)
				require.Equal(t, length, parsed.LengthPresent())
				require.Equal(t, cid, parsed.ConnectionID())
				require.Equal(t, header, parsed.HeaderBytes())
				require.Equal(t, ciphertext, parsed.Payload())
				require.Equal(t, config.TwoByteSequence, two)
				require.Equal(t, config.LengthPresent, length)
				records, err := UnpackDatagram(raw, UnpackDatagramConfig{CIDLength: len(cid)})
				require.NoError(t, err)
				require.Equal(t, [][]byte{raw}, records)
				ciphertext[0] ^= 0xff
				require.Equal(t, byte(0xde), parsed.Payload()[0])
				if length {
					_, err = ParseRecord(append(bytes.Clone(raw), 0), len(cid))
					require.Error(t, err)
				}
			}
		}
	}
}

func TestUnifiedRecordRejectsInvalidInputs(t *testing.T) {
	for _, config := range []CiphertextConfig{{EpochLow: 4}, {SequenceNumber: 256}, {ConnectionID: make([]byte, 256)}} {
		raw, err := MarshalCiphertext(config, make([]byte, 16))
		require.Error(t, err)
		require.Nil(t, raw)
	}
	for _, n := range []int{0, 1, 15, maxDTLSCiphertextRecordLen + 1} {
		raw, err := MarshalCiphertext(CiphertextConfig{}, make([]byte, n))
		require.ErrorIs(t, err, ErrInvalidPacketLength)
		require.Nil(t, raw)
	}
	raw, err := MarshalCiphertext(CiphertextConfig{ConnectionID: []byte{1, 2}, LengthPresent: true}, make([]byte, 16))
	require.NoError(t, err)
	for _, n := range []int{-1, 0, 1, 3, 256} {
		parsed, err := ParseRecord(raw, n)
		require.Error(t, err)
		require.Empty(t, parsed.Raw())
	}
	for n := range len(raw) {
		parsed, err := ParseRecord(raw[:n], 2)
		require.Error(t, err)
		require.Empty(t, parsed.Raw())
	}
}

func fuzzUnifiedRecord(f *testing.F, cidLength int) {
	f.Helper()
	for _, two := range []bool{false, true} {
		for _, length := range []bool{false, true} {
			raw, err := MarshalCiphertext(CiphertextConfig{EpochLow: 2, SequenceNumber: 0x42, TwoByteSequence: two, LengthPresent: length, ConnectionID: bytes.Repeat([]byte{0xab}, cidLength)}, make([]byte, 16))
			if err != nil {
				f.Fatal(err)
			}
			f.Add(raw)
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		parsed, err := ParseRecord(raw, cidLength)
		if err != nil || !parsed.IsUnified() {
			return
		}
		before := bytes.Clone(raw)
		encoded, err := MarshalCiphertext(CiphertextConfig{EpochLow: parsed.EpochLow(), SequenceNumber: uint16(parsed.SequenceNumber() & 0xffff), TwoByteSequence: parsed.SequenceBytes() == 2, LengthPresent: parsed.LengthPresent(), ConnectionID: parsed.ConnectionID()}, parsed.Payload())
		require.NoError(t, err)
		require.Equal(t, before, raw)
		require.Equal(t, raw, encoded)
	})
}

func FuzzUnifiedHeaderUnmarshal(f *testing.F)    { fuzzUnifiedRecord(f, 0) }
func FuzzUnifiedHeaderCIDUnmarshal(f *testing.F) { fuzzUnifiedRecord(f, 32) }
