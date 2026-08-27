// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"bytes"
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

const maxCookieSize = 0xffff - 2

// Cookie is the cookie extension payload used in HelloRetryRequest and the
// subsequent ClientHello.
type Cookie struct {
	Cookie []byte
}

// ExtensionType returns the IANA extension type.
func (Cookie) ExtensionType() extension.Type { return extension.TypeCookie }

// MarshalSize returns the encoded payload size without serializing it.
func (c Cookie) MarshalSize() int { return 2 + len(c.Cookie) }

// MarshalData encodes extension_data.
func (c Cookie) MarshalData() ([]byte, error) {
	if len(c.Cookie) == 0 || len(c.Cookie) > maxCookieSize {
		return nil, dtlserrors.ErrCookieExtFormat
	}

	out := make([]byte, 2, 2+len(c.Cookie))
	binary.BigEndian.PutUint16(out, uint16(len(c.Cookie))) //nolint:gosec // length is bounded above.
	out = append(out, c.Cookie...)

	return out, nil
}

// UnmarshalData decodes extension_data.
func (c *Cookie) UnmarshalData(data []byte) error {
	if len(data) < 2 {
		return dtlserrors.ErrCookieExtFormat
	}

	length := int(binary.BigEndian.Uint16(data))
	if length == 0 || length > maxCookieSize || length != len(data)-2 {
		return dtlserrors.ErrCookieExtFormat
	}

	c.Cookie = bytes.Clone(data[2:])

	return nil
}
