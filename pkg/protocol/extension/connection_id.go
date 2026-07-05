// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"golang.org/x/crypto/cryptobyte"
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

// TypeValue returns the extension TypeValue.
func (c ConnectionID) TypeValue() TypeValue {
	return ConnectionIDTypeValue
}

// Marshal encodes the extension.
func (c *ConnectionID) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(uint16(c.TypeValue()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(c.CID)
		})
	})

	return b.Bytes()
}

// Unmarshal populates the extension from encoded data.
func (c *ConnectionID) Unmarshal(data []byte) error {
	payload, err := extensionPayload(data, c.TypeValue())
	if err != nil {
		return err
	}

	return c.unmarshalPayload(payload)
}

func (c *ConnectionID) unmarshalPayload(data []byte) error {
	extData := cryptobyte.String(data)

	var cid cryptobyte.String
	if !extData.ReadUint8LengthPrefixed(&cid) {
		return dtlserrors.ErrInvalidCIDFormat
	}

	if !extData.Empty() {
		return dtlserrors.ErrLengthMismatch
	}

	c.CID = make([]byte, len(cid))
	if !cid.CopyBytes(c.CID) {
		return dtlserrors.ErrInvalidCIDFormat
	}

	return nil
}
