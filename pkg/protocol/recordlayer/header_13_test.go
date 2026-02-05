// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnifiedHeader(t *testing.T) {
	uh := UnifiedHeader{SequenceNumber: 0xaabb, Length: 42, EpochLow: 15}

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
	assert.Equal(t, uh.ConnectionID, newUh.ConnectionID)
	assert.Equal(t, uh.SequenceNumber, newUh.SequenceNumber)
	assert.Equal(t, uh.Length, newUh.Length)
	assert.Equal(t, uint8(0b11), newUh.EpochLow)
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
	assert.Equal(t, uh.ConnectionID, newUh.ConnectionID)
	assert.Equal(t, uh.SequenceNumber, newUh.SequenceNumber)
	assert.Equal(t, uh.Length, newUh.Length)
	assert.Equal(t, uint8(0b00), newUh.EpochLow)
}

func TestUnifiedHeader_CID(t *testing.T) {
	CID := []byte{0x1, 0x2, 0x3, 0x4}
	uh := UnifiedHeader{ConnectionID: CID, SequenceNumber: 0xaa}

	raw, err := uh.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x30,      // 0b00110000
		0x04,      // CID length
		0x01, 0x2, // CID
		0x03, 0x4, // CID
		0xaa, // Seq no
	}
	assert.Equal(t, expect, raw)

	newUh := UnifiedHeader{}
	err = newUh.Unmarshal(expect)

	assert.NoError(t, err)
	assert.Equal(t, uh.ConnectionID, newUh.ConnectionID)
	assert.Equal(t, uh.SequenceNumber, newUh.SequenceNumber)
	assert.Equal(t, uh.Length, newUh.Length)
	assert.Equal(t, uint8(0b00), newUh.EpochLow)
}
