// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/stretchr/testify/assert"
)

func TestUnifiedHeader(t *testing.T) {
	uh := UnifiedHeader{SequenceNumber: 0xaabb, SeqBit: true, Length: 42, LengthBit: true, EpochLow: 15}

	raw, err := uh.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x2f,       // 0b00101111
		0xaa, 0xbb, // Sequence number
		0x00, 0x2a, // length
	}
	assert.Equal(t, expect, raw)

	newUh := UnifiedHeader{}
	err = newUh.Unmarshal(expect)

	assert.NoError(t, err)
	assert.Empty(t, newUh.ConnectionID)
	assert.Equal(t, uh.SequenceNumber, newUh.SequenceNumber)
	assert.True(t, newUh.SeqBit)
	assert.Equal(t, uh.Length, newUh.Length)
	assert.True(t, newUh.LengthBit)
	assert.Equal(t, uh.EpochLow&0b11, newUh.EpochLow)
}

func TestUnifiedHeader_Minimal(t *testing.T) {
	uh := UnifiedHeader{SequenceNumber: 0x42}

	raw, err := uh.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x20, // 0b00100000
		0x42, // Sequence number
	}
	assert.Equal(t, expect, raw)

	newUh := UnifiedHeader{}
	err = newUh.Unmarshal(expect)

	assert.NoError(t, err)
	assert.Empty(t, newUh.ConnectionID)
	assert.Equal(t, uh.SequenceNumber, newUh.SequenceNumber)
	assert.False(t, newUh.SeqBit)
	assert.Equal(t, uh.Length, newUh.Length)
	assert.False(t, newUh.LengthBit)
	assert.Equal(t, uint8(0b00), newUh.EpochLow)
}

func TestUnifiedHeader_CID(t *testing.T) {
	CID := []byte{0x1, 0x2, 0x3, 0x4}
	uh := UnifiedHeader{ConnectionID: CID, SequenceNumber: 0xaa}

	raw, err := uh.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x30,      // 0b00110000
		0x01, 0x2, // CID
		0x03, 0x4, // CID
		0xaa, // Seq no
	}
	assert.Equal(t, expect, raw)

	newUh := UnifiedHeader{ConnectionID: make([]byte, len(CID))}
	err = newUh.Unmarshal(expect)

	assert.NoError(t, err)
	assert.Equal(t, uh.ConnectionID, newUh.ConnectionID)
	assert.Equal(t, uh.SequenceNumber, newUh.SequenceNumber)
	assert.False(t, newUh.SeqBit)
	assert.Equal(t, uh.Length, newUh.Length)
	assert.False(t, newUh.LengthBit)
	assert.Equal(t, uint8(0b00), newUh.EpochLow)
}

func TestUnifiedHeaderSizeUsesEncodedBits(t *testing.T) {
	uh := UnifiedHeader{
		SeqBit:    true,
		LengthBit: true,
	}
	assert.Equal(t, 5, uh.MarshalSize())

	uh = UnifiedHeader{
		SequenceNumber: 0x0100,
		Length:         1,
	}
	assert.Equal(t, 2, uh.MarshalSize())
}

func TestUnifiedHeaderUnmarshalClearsBits(t *testing.T) {
	uh := UnifiedHeader{
		SeqBit:    true,
		Length:    5,
		LengthBit: true,
	}

	err := uh.Unmarshal([]byte{0x20, 0x42})
	assert.NoError(t, err)
	assert.False(t, uh.SeqBit)
	assert.False(t, uh.LengthBit)
	assert.Equal(t, 2, uh.MarshalSize())
}

func FuzzUnifiedHeaderUnmarshal(f *testing.F) {
	testcases := [][]byte{
		{
			0x2f,       // 0b00101111
			0xaa, 0xbb, // Sequence number
			0x00, 0x2a, // length
		},
		{
			0x20, // 0b00100000
			0x42, // Sequence number
		},
		{
			0x30,      // 0b00110000
			0x01, 0x2, // CID
			0x03, 0x4, // CID
			0xaa, // Seq no
		},
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		uh := UnifiedHeader{}
		err := uh.Unmarshal(data)
		if err != nil {
			return
		}
		content := data[0]
		assert.Less(t, int(content), 64)
		assert.Greater(t, int(content), 31)
		parsedLength := len(uh.ConnectionID)
		assert.Zero(t, parsedLength)
		assert.LessOrEqual(t, uh.EpochLow, uint8(0b000000011))
	})
}

func FuzzUnifiedHeaderCIDUnmarshal(f *testing.F) {
	const cidLength = 32

	testcases := [][]byte{
		{
			0x2f,       // 0b00101111
			0xaa, 0xbb, // Sequence number
			0x00, 0x2a, // length
		},
		{
			0x20, // 0b00100000
			0x42, // Sequence number
		},
		{
			0x30,      // 0b00110000
			0x01, 0x2, // CID
			0x03, 0x4, // CID
			0xaa, // Seq no
		},
	}

	for _, tc := range testcases {
		f.Add(tc)
	}

	cid := make([]byte, cidLength)
	for i := range cid {
		cid[i] = byte(i)
	}
	raw, err := (&UnifiedHeader{
		ConnectionID:   cid,
		SequenceNumber: 0xaabb,
		SeqBit:         true,
		Length:         42,
		LengthBit:      true,
		EpochLow:       3,
	}).Marshal()
	if err != nil {
		f.Fatalf("marshal fuzz seed: %v", err)
	}
	f.Add(raw)

	f.Fuzz(func(t *testing.T, data []byte) {
		uh := UnifiedHeader{ConnectionID: make([]byte, cidLength)}
		err := uh.Unmarshal(data)
		if err != nil {
			return
		}
		content := data[0]
		assert.Less(t, int(content), 64)
		assert.Greater(t, int(content), 31)
		if (content & UnifiedHeaderCIDBit) != 0 {
			parsedLength := len(uh.ConnectionID)
			assert.Equal(t, cidLength, parsedLength)
		}
		assert.LessOrEqual(t, uh.EpochLow, uint8(0b000000011))

		raw, err := uh.Marshal()
		assert.NoError(t, err)
		assert.Equal(t, data[:uh.MarshalSize()], raw)
	})
}

func TestUnifiedHeaderMarshalTo(t *testing.T) {
	header := UnifiedHeader{
		ConnectionID:   []byte{0xca, 0xfe, 0xba, 0xbe},
		SequenceNumber: 0xaabb,
		SeqBit:         true,
		Length:         42,
		LengthBit:      true,
		EpochLow:       3,
	}
	want, err := header.Marshal()
	assert.NoError(t, err)

	out := make([]byte, header.MarshalSize()+1)
	n, err := header.MarshalTo(out)
	assert.NoError(t, err)
	assert.Equal(t, len(want), n)
	assert.Equal(t, want, out[:n])

	_, err = header.MarshalTo(out[:n-1])
	assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)

	header = UnifiedHeader{ConnectionID: make([]byte, 256)}

	_, err = header.MarshalTo(make([]byte, header.MarshalSize()))
	assert.ErrorIs(t, err, dtlserrors.ErrCIDTooBig)
}
