// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls12

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// RenegotiationInfo communicates secure renegotiation support.
type RenegotiationInfo struct {
	RenegotiatedConnection uint8
}

// ExtensionType returns the IANA extension type.
func (RenegotiationInfo) ExtensionType() extension.Type {
	return extension.TypeRenegotiationInfo
}

// MarshalSize returns the encoded payload size.
func (RenegotiationInfo) MarshalSize() int { return 1 }

// MarshalData encodes extension_data.
func (r RenegotiationInfo) MarshalData() ([]byte, error) {
	return []byte{r.RenegotiatedConnection}, nil
}

// UnmarshalData decodes extension_data.
func (r *RenegotiationInfo) UnmarshalData(data []byte) error {
	if len(data) != 1 {
		return dtlserrors.ErrLengthMismatch
	}

	r.RenegotiatedConnection = data[0]

	return nil
}
