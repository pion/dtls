// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension //nolint:dupl

import (
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

const (
	postHandshakeAuthHeaderSize = 4
)

// PostHandshakeAuth defines a DTLS 1.3 extension that is used to indicate
// that a client is willing to perform post-handshake authentication.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.6
type PostHandshakeAuth struct {
	Enabled bool
}

// TypeValue returns the extension TypeValue.
func (p PostHandshakeAuth) TypeValue() TypeValue {
	return PostHandshakeAuthTypeValue
}

// Marshal encodes the extension.
func (p *PostHandshakeAuth) Marshal() ([]byte, error) {
	if !p.Enabled {
		return []byte{}, nil
	}

	out := make([]byte, postHandshakeAuthHeaderSize)

	binary.BigEndian.PutUint16(out, uint16(p.TypeValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(0))

	return out, nil
}

// Unmarshal populates the extension from encoded data.
func (p *PostHandshakeAuth) Unmarshal(data []byte) error {
	payload, err := extensionPayload(data, p.TypeValue())
	if err != nil {
		return err
	}

	return p.unmarshalPayload(payload)
}

func (p *PostHandshakeAuth) unmarshalPayload(data []byte) error {
	if len(data) != 0 {
		return dtlserrors.ErrLengthMismatch
	}
	p.Enabled = true

	return nil
}
