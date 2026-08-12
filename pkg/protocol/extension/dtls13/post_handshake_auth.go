// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// PostHandshakeAuth is the empty post_handshake_auth payload.
type PostHandshakeAuth struct{}

// ExtensionType returns the IANA extension type.
func (PostHandshakeAuth) ExtensionType() extension.Type {
	return extension.TypePostHandshakeAuth
}

// MarshalData encodes extension_data.
func (PostHandshakeAuth) MarshalData() ([]byte, error) { return []byte{}, nil }

// UnmarshalData decodes extension_data.
func (*PostHandshakeAuth) UnmarshalData(data []byte) error {
	if len(data) != 0 {
		return dtlserrors.ErrLengthMismatch
	}

	return nil
}
