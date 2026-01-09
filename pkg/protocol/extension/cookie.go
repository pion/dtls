// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

type CookieExt struct {
	Cookie []byte
}

// TypeValue returns the extension TypeValue.
func (c CookieExt) TypeValue() TypeValue {
	return CookieTypeValue
}

var errCoookieExtFormat = errors.New("invalid cookie format")

// Marshal encodes the extension.
func (c *CookieExt) Marshal() ([]byte, error) {
	cookieLength := len(c.Cookie)
	if cookieLength == 0 || cookieLength > 0xfffd {
		return nil, errCoookieExtFormat
	}
	var b cryptobyte.Builder
	b.AddUint16(uint16(c.TypeValue()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(c.Cookie)
		})
	})

	return b.Bytes()
}

// Unmarshal populates the extension from encoded data.
func (c *CookieExt) Unmarshal(data []byte) error { //nolint:cyclop
	val := cryptobyte.String(data)
	var extension uint16
	val.ReadUint16(&extension)
	if TypeValue(extension) != c.TypeValue() {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errBufferTooSmall
	}

	var cookie cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&cookie) {
		return errCoookieExtFormat
	}

	cookieLength := len(cookie)
	if cookieLength == 0 || cookieLength > 0xfffd {
		return errCoookieExtFormat
	}

	c.Cookie = cookie

	return nil
}
