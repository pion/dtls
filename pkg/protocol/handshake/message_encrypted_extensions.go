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
	Extensions []extension.Value
}

// Type returns the Handshake Type.
func (m MessageEncryptedExtensions) Type() Type {
	return TypeEncryptedExtensions
}

// MarshalSize returns the minimal size required for MarshalTo.
func (m *MessageEncryptedExtensions) MarshalSize() int {
	return extension.MarshalListSize(m.Extensions)
}

// Marshal encodes the Handshake.
func (m *MessageEncryptedExtensions) Marshal() ([]byte, error) {
	prepared, err := extension.PrepareList(m.Extensions)
	if err != nil {
		return nil, err
	}

	out := make([]byte, prepared.MarshalSize())
	_, _ = prepared.MarshalTo(out)

	return out, nil
}

// MarshalTo encodes the Handshake into a pre-allocated buffer.
func (m *MessageEncryptedExtensions) MarshalTo(out []byte) (int, error) {
	prepared, err := extension.PrepareList(m.Extensions)
	if err != nil {
		return 0, err
	}
	if len(out) < prepared.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	return prepared.MarshalTo(out)
}

// Unmarshal populates the message from encoded data.
func (m *MessageEncryptedExtensions) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return dtlserrors.ErrBufferTooSmall
	}

	extensions, err := decodeExtensionList(data, extensionContextEncryptedExtensions)
	if err != nil {
		return err
	}
	m.Extensions = extensions

	return nil
}
