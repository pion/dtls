// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension // nolint:dupl

import (
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

const (
	useExtendedMasterSecretHeaderSize = 4
)

// UseExtendedMasterSecret defines a TLS extension that contextually binds the
// master secret to a log of the full handshake that computes it, thus
// preventing MITM attacks.
type UseExtendedMasterSecret struct {
	Supported bool
}

// TypeValue returns the extension TypeValue.
func (u UseExtendedMasterSecret) TypeValue() TypeValue {
	return UseExtendedMasterSecretTypeValue
}

// Marshal encodes the extension.
func (u *UseExtendedMasterSecret) Marshal() ([]byte, error) {
	if !u.Supported {
		return []byte{}, nil
	}

	out := make([]byte, useExtendedMasterSecretHeaderSize)

	binary.BigEndian.PutUint16(out, uint16(u.TypeValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(0)) // length

	return out, nil
}

// Unmarshal populates the extension from encoded data.
func (u *UseExtendedMasterSecret) Unmarshal(data []byte) error {
	payload, err := extensionPayload(data, u.TypeValue())
	if err != nil {
		return err
	}

	return u.unmarshalPayload(payload)
}

func (u *UseExtendedMasterSecret) unmarshalPayload(data []byte) error {
	if len(data) != 0 {
		return dtlserrors.ErrLengthMismatch
	}
	u.Supported = true

	return nil
}
