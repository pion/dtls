// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCookieExt(t *testing.T) {
	extension := CookieExt{Cookie: []byte{0x1, 0x42}}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x2c, // extension type
		0x00, 0x04, // extension length
		0x00, 0x02, // vec length
		0x01, 0x42, // cookie
	}
	assert.Equal(t, raw, expect)

	newExtension := CookieExt{}

	assert.NoError(t, newExtension.Unmarshal(expect))
	assert.Equal(t, extension.Cookie, newExtension.Cookie)
}

func FuzzCookieExtUnmarshal(f *testing.F) {
	bigCookie := make([]byte, 0xffff)
	bigCookie[0] = 0x00
	bigCookie[1] = 0x2c
	bigCookie[2] = 0xff
	bigCookie[3] = 0xff
	bigCookie[4] = 0xff
	bigCookie[5] = 0xfd

	testcases := [][]byte{
		{
			0x00, 0x2c, // extension type
			0x00, 0x04, // extension length
			0x00, 0x02, // vec length
			0x01, 0x42, // cookie
		},
		{
			0x00, 0x2c, // extension type
			0x00, 0x04, // extension length
			0x00, 0x01, // vec length
			0x01, // cookie
		},
		bigCookie,
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, a []byte) {
		cookieExt := CookieExt{}
		err := cookieExt.Unmarshal(a)
		if err == nil {
			length := len(cookieExt.Cookie)
			assert.NotZero(t, length)
			assert.LessOrEqual(t, length, 0xfffd)
		}
	})
}
