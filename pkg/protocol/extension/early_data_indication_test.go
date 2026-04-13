// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEarlyDataIndication_NewSessionTicket(t *testing.T) {
	earlyData := uint32(128)
	extension := EarlyDataIndication{MaxEarlyData: &earlyData}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x2a, // extension type
		0x00, 0x04, // extension length
		0x00, 0x00, // MaxEarlyData
		0x00, 0x80, // MaxEarlyData
	}
	assert.Equal(t, expect, raw)

	newExtension := EarlyDataIndication{}

	assert.NoError(t, newExtension.Unmarshal(expect))
	assert.Equal(t, extension.MaxEarlyData, newExtension.MaxEarlyData)
}

func TestEarlyDataIndication_CHEE(t *testing.T) {
	extension := EarlyDataIndication{}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x2a, // extension type
		0x00, 0x00, // extension length
	}
	assert.Equal(t, expect, raw)

	newExtension := EarlyDataIndication{}

	assert.NoError(t, newExtension.Unmarshal(expect))
	assert.Nil(t, newExtension.MaxEarlyData)
}

func FuzzEarlyDataIndicationUnmarshal(f *testing.F) {
	testCases := [][]byte{
		// NewSessionTicket
		{
			0x00, 0x2a, // extension type
			0x00, 0x04, // extension length
			0x00, 0x00, // MaxEarlyData
			0x00, 0x80, // MaxEarlyData
		},
		// ClientHello, EncryptedExtensions
		{
			0x00, 0x2a, // extension type
			0x00, 0x00, // extension length
		},
	}
	for _, tc := range testCases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var e EarlyDataIndication
		err := e.Unmarshal(data)
		if err != nil {
			return
		}
		testExtDataLength(t, &e, data, true)
	})
}
