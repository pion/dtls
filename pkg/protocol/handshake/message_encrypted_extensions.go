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
	extensions []extension.Value
}

// Extensions returns the extensions.
func (m MessageEncryptedExtensions) Extensions() []extension.Value {
	return m.extensions
}

// SetExtensions replaces the extensions.
func (m *MessageEncryptedExtensions) SetExtensions(extensions []extension.Value) {
	m.extensions = extensions
}

// Type returns the Handshake Type.
func (m MessageEncryptedExtensions) Type() Type {
	return TypeEncryptedExtensions
}

// MarshalSize returns the minimal size required for MarshalTo.
func (m *MessageEncryptedExtensions) MarshalSize() int {
	return extension.MarshalListSize(m.extensions)
}

// Marshal encodes the Handshake.
func (m *MessageEncryptedExtensions) Marshal() ([]byte, error) {
	out := make([]byte, m.MarshalSize())
	_, err := m.MarshalTo(out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// MarshalTo encodes the Handshake into a pre-allocated buffer.
func (m *MessageEncryptedExtensions) MarshalTo(out []byte) (int, error) {
	if len(out) < m.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	return extension.MarshalListTo(out, m.extensions)
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
	m.SetExtensions(extensions)

	return nil
}
