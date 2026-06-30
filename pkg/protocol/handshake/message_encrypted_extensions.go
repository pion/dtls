// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// MessageEncryptedExtensions message contains extensions that can be
// protected, i.e., any which are not needed to establish the
// cryptographic context
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.1
type MessageEncryptedExtensions struct {
	Extensions []extension.Extension
}

// Type returns the Handshake Type.
func (m MessageEncryptedExtensions) Type() Type {
	return TypeEncryptedExtensions
}

// Marshal encodes the Handshake.
func (m *MessageEncryptedExtensions) Marshal() ([]byte, error) {
	return extension.Marshal(m.Extensions)
}

// Unmarshal populates the message from encoded data.
func (m *MessageEncryptedExtensions) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return dtlserrors.ErrBufferTooSmall
	}

	extensions, err := extension.Unmarshal(data)
	if err != nil {
		return err
	}
	m.Extensions = extensions

	return nil
}
