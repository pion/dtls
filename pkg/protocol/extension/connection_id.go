// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"bytes"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

// ConnectionID is a DTLS extension that provides an alternative to IP address
// and port for session association.
//
// https://tools.ietf.org/html/rfc9146
type ConnectionID struct {
	// A zero-length connection ID indicates for a client or server that
	// negotiated connection IDs from the peer will be sent but there is no need
	// to respond with one
	CID []byte // variable length
}

// ExtensionType returns the IANA extension type for the payload-oriented API.
func (c ConnectionID) ExtensionType() Type {
	return TypeConnectionID
}

// MarshalSize returns the encoded payload size without serializing it.
func (c ConnectionID) MarshalSize() int { return 1 + len(c.CID) }

// MarshalData encodes extension_data without the extension header.
func (c ConnectionID) MarshalData() ([]byte, error) {
	if len(c.CID) > 255 {
		return nil, dtlserrors.ErrInvalidCIDFormat
	}

	out := make([]byte, 1, 1+len(c.CID))
	out[0] = byte(len(c.CID)) //nolint:gosec // length is bounded above.
	out = append(out, c.CID...)

	return out, nil
}

// UnmarshalData decodes extension_data without the extension header.
func (c *ConnectionID) UnmarshalData(data []byte) error {
	if len(data) == 0 {
		return dtlserrors.ErrInvalidCIDFormat
	}

	cidLen := int(data[0])
	if cidLen > len(data)-1 {
		return dtlserrors.ErrInvalidCIDFormat
	}
	if cidLen != len(data)-1 {
		return dtlserrors.ErrLengthMismatch
	}

	c.CID = bytes.Clone(data[1:])

	return nil
}
