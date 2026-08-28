// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
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

func TestACK_Unmarshal(t *testing.T) {
	for name, test := range map[string]struct {
		raw     []byte
		wantErr error
	}{
		"empty": {
			raw: []byte{0x00, 0x00}, // record list length = 0
		},
		"truncated record": {
			raw: []byte{
				0x00, 0x10, // record list length = 16
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // only 7 bytes of epoch
			},
			wantErr: dtlserrors.ErrLengthMismatch,
		},
		"trailing data": {
			raw: []byte{
				0x00, 0x10, // record list length = 16 (one record)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // epoch = 1
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence_number = 1
				0xde, 0xad, // trailing garbage
			},
			wantErr: dtlserrors.ErrLengthMismatch,
		},
	} {
		t.Run(name, func(t *testing.T) {
			newACK := ACK{}
			err := newACK.Unmarshal(test.raw)
			if test.wantErr != nil {
				assert.ErrorIs(t, err, test.wantErr)

				return
			}

			assert.NoError(t, err)
			assert.Empty(t, newACK.Records)
		})
	}

	t.Run("maximum records", func(t *testing.T) {
		ack := ACK{Records: make([]RecordNumber, 4095)}

		raw, err := ack.Marshal()
		assert.NoError(t, err)
		assert.Len(t, raw, 2+4095*16)
		assert.Equal(t, ack.MarshalSize(), len(raw))
		assert.Equal(t, []byte{0xff, 0xf0}, raw[:2])
	})

	t.Run("too many records", func(t *testing.T) {
		ack := ACK{Records: make([]RecordNumber, 4096)}

		raw, err := ack.Marshal()
		assert.ErrorIs(t, err, dtlserrors.ErrInvalidACK)
		assert.Nil(t, raw)

		_, err = ack.MarshalTo(make([]byte, ack.MarshalSize()))
		assert.ErrorIs(t, err, dtlserrors.ErrInvalidACK)
	})
}
