// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtensionConnectionID(t *testing.T) {
	rawExtensionConnectionID := []byte{1, 6, 8, 3, 88, 12, 2, 47}
	parsedExtensionConnectionID := &ConnectionID{
		CID: rawExtensionConnectionID,
	}

	raw, err := parsedExtensionConnectionID.Marshal()
	assert.NoError(t, err)

	roundtrip := &ConnectionID{}
	assert.NoError(t, roundtrip.Unmarshal(raw))
	assert.Equal(t, parsedExtensionConnectionID, roundtrip)
}

func FuzzCIDUnmarshal(f *testing.F) {
	bigCID := make([]byte, 0xff)
	bigCID[0] = 0x00
	bigCID[1] = 0x36
	bigCID[2] = 0xff
	bigCID[3] = 0xff
	bigCID[4] = 0xff
	bigCID[5] = 0xfd

	testCases := [][]byte{
		{
			0x00, 0x36, // Extension type
			0x00, 0x03, // Extension length
			0x00, 0x01, // CID length
			0x42, // CID
		},
		bigCID,
	}
	for _, tc := range testCases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		cid := ConnectionID{}
		err := cid.Unmarshal(data)
		if err != nil {
			return
		}
		length := len(cid.CID)
		assert.Less(t, length, 0xff)
		testExtDataLength(t, &cid, data, true)
	})
}
