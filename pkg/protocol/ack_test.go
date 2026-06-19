// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestACK(t *testing.T) {
	ack := ACK{
		Records: []RecordNumber{
			{Epoch: 1, SequenceNumber: 42},
		},
	}

	raw, err := ack.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x10, // record list length (1 record × 16 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // epoch = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, // sequence_number = 42
	}
	assert.Equal(t, expect, raw)

	newACK := ACK{}
	assert.NoError(t, newACK.Unmarshal(expect))
	assert.Len(t, newACK.Records, 1)
	assert.Equal(t, uint64(1), newACK.Records[0].Epoch)
	assert.Equal(t, uint64(42), newACK.Records[0].SequenceNumber)
}

func TestACK_MultipleRecords(t *testing.T) {
	ack := ACK{
		Records: []RecordNumber{
			{Epoch: 1, SequenceNumber: 1},
			{Epoch: 1, SequenceNumber: 2},
			{Epoch: 2, SequenceNumber: 0},
		},
	}

	raw, err := ack.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x30, // record list length (3 × 16 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // epoch = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence_number = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // epoch = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // sequence_number = 2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // epoch = 2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sequence_number = 0
	}
	assert.Equal(t, expect, raw)

	newACK := ACK{}
	assert.NoError(t, newACK.Unmarshal(expect))
	assert.Len(t, newACK.Records, 3)
	assert.Equal(t, uint64(1), newACK.Records[0].Epoch)
	assert.Equal(t, uint64(1), newACK.Records[0].SequenceNumber)
	assert.Equal(t, uint64(1), newACK.Records[1].Epoch)
	assert.Equal(t, uint64(2), newACK.Records[1].SequenceNumber)
	assert.Equal(t, uint64(2), newACK.Records[2].Epoch)
	assert.Equal(t, uint64(0), newACK.Records[2].SequenceNumber)
}

func TestACK_EmptyRecords(t *testing.T) {
	ack := ACK{Records: []RecordNumber{}}

	raw, err := ack.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x00, // record list length (empty)
	}
	assert.Equal(t, expect, raw)

	newACK := ACK{}
	assert.NoError(t, newACK.Unmarshal(expect))
	assert.Empty(t, newACK.Records)
}

func TestACK_UnmarshalTruncatedRecord(t *testing.T) {
	// Length prefix claims 16 bytes but only 7 are present.
	raw := []byte{
		0x00, 0x10, // record list length = 16
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // only 7 bytes of epoch
	}
	newACK := ACK{}
	assert.ErrorIs(t, newACK.Unmarshal(raw), errLengthMismatch)
}

func TestACK_UnmarshalTrailingData(t *testing.T) {
	// Valid record list followed by unexpected trailing bytes.
	raw := []byte{
		0x00, 0x10, // record list length = 16 (one record)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // epoch = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence_number = 1
		0xde, 0xad, // trailing garbage
	}
	newACK := ACK{}
	assert.ErrorIs(t, newACK.Unmarshal(raw), errLengthMismatch)
}

func TestACK_UnmarshalEmpty(t *testing.T) {
	newACK := ACK{}
	assert.NoError(t, newACK.Unmarshal([]byte{0x00, 0x00}))
}
