// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"golang.org/x/crypto/cryptobyte"
)

const maxCookieSize = 0xffff - 2

// CookieExt implements the cookie extension in DTLS 1.3.
// See RFC 8446 section 4.2.2. Cookie.
type CookieExt struct {
	Cookie []byte
}

// TypeValue returns the extension TypeValue.
func (c CookieExt) TypeValue() TypeValue {
	return CookieTypeValue
}

// Marshal encodes the extension.
func (c *CookieExt) Marshal() ([]byte, error) {
	cookieLength := len(c.Cookie)
	if cookieLength == 0 || cookieLength > maxCookieSize {
		return nil, dtlserrors.ErrCookieExtFormat
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
	payload, err := extensionPayload(data, c.TypeValue())
	if err != nil {
		return err
	}

	return c.unmarshalPayload(payload)
}

func (c *CookieExt) unmarshalPayload(data []byte) error { //nolint:cyclop
	extData := cryptobyte.String(data)

	var cookie cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&cookie) || cookie.Empty() || len(cookie) > maxCookieSize {
		return dtlserrors.ErrCookieExtFormat
	}

	if !extData.Empty() {
		return dtlserrors.ErrLengthMismatch
	}

	c.Cookie = append([]byte(nil), cookie...)

	return nil
}
