// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls12

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// ExtendedMasterSecret represents the presence of the empty
// extended_master_secret extension.
type ExtendedMasterSecret struct{}

// ExtensionType returns the IANA extension type.
func (ExtendedMasterSecret) ExtensionType() extension.Type {
	return extension.TypeExtendedMasterSecret
}

// MarshalData encodes extension_data.
func (ExtendedMasterSecret) MarshalData() ([]byte, error) { return []byte{}, nil }

// UnmarshalData decodes extension_data.
func (*ExtendedMasterSecret) UnmarshalData(data []byte) error {
	if len(data) != 0 {
		return dtlserrors.ErrLengthMismatch
	}

	return nil
}
