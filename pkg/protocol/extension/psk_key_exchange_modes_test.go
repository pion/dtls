// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPskKeyExchangeModes(t *testing.T) {
	raw := []byte{
		0x00, 0x2d, // extension type
		0x00, 0x02, // extension length
		0x01, // modes length
		0x00, // mode
	}

	extension := PskKeyExchangeModes{}

	expect := PskKeyExchangeModes{KeModes: []PskKeyExchangeMode{PskKe}}

	assert.NoError(t, extension.Unmarshal(raw))
	assert.Equal(t, 1, len(extension.KeModes))
	assert.Equal(t, expect.KeModes[0], extension.KeModes[0])

	test, err := expect.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, raw, test)
}

func TestPskKeyExchangeModes_Empty(t *testing.T) {
	raw := []byte{
		0x00, 0x2d, // extension type
		0x00, 0x01, // extension length
		0x00, // modes length
	}

	extension := PskKeyExchangeModes{}

	err := extension.Unmarshal(raw)
	assert.ErrorIs(t, err, errPskKeyExchangeModesFormat)
}

func FuzzPskKeyExchangeModesUnmarshal(f *testing.F) {
	modes := make([]byte, 0x105)
	modes[0] = 0x00
	modes[1] = 0x2d
	modes[2] = 0x01
	modes[3] = 0x00
	modes[4] = 0xff

	testcases := [][]byte{
		{
			0x00, 0x2d, // extension type
			0x00, 0x02, // extension length
			0x01, // modes length
			0x00, // mode
		},
		{
			0x00, 0x2d, // extension type
			0x00, 0x01, // extension length
			0x00, // modes length
		},
		{
			0x00, 0x2d, // extension type
			0x00, 0x01, // extension length
			0xff, // modes length
		},
		modes,
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, a []byte) {
		pskModes := PskKeyExchangeModes{}
		err := pskModes.Unmarshal(a)
		if err == nil {
			length := len(pskModes.KeModes)
			assert.NotZero(t, length)
			assert.LessOrEqual(t, length, 255)
		}
	})
}
