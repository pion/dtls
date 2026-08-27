// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// EarlyData is the empty early_data payload in ClientHello and
// EncryptedExtensions.
type EarlyData struct{}

// ExtensionType returns the IANA extension type.
func (EarlyData) ExtensionType() extension.Type { return extension.TypeEarlyData }

// MarshalSize returns the encoded payload size.
func (EarlyData) MarshalSize() int { return 0 }

// MarshalData encodes extension_data.
func (EarlyData) MarshalData() ([]byte, error) { return []byte{}, nil }

// UnmarshalData decodes extension_data.
func (*EarlyData) UnmarshalData(data []byte) error {
	if len(data) != 0 {
		return dtlserrors.ErrEarlyDataIndicationFormat
	}

	return nil
}

// MaxEarlyData is the NewSessionTicket early_data payload.
type MaxEarlyData struct {
	Size uint32
}

// ExtensionType returns the IANA extension type.
func (MaxEarlyData) ExtensionType() extension.Type { return extension.TypeEarlyData }

// MarshalSize returns the encoded payload size.
func (MaxEarlyData) MarshalSize() int { return 4 }

// MarshalData encodes extension_data.
func (m MaxEarlyData) MarshalData() ([]byte, error) {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, m.Size)

	return out, nil
}

// UnmarshalData decodes extension_data.
func (m *MaxEarlyData) UnmarshalData(data []byte) error {
	if len(data) != 4 {
		return dtlserrors.ErrEarlyDataIndicationFormat
	}
	m.Size = binary.BigEndian.Uint32(data)

	return nil
}
