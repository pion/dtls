// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import dtlserrors "github.com/pion/dtls/v3/internal/errors"

// ReturnRoutabilityCheck negotiates the RFC 9853 RRC subprotocol.
type ReturnRoutabilityCheck struct{}

// ExtensionType returns the IANA extension type for RRC.
func (ReturnRoutabilityCheck) ExtensionType() Type { return TypeReturnRoutabilityCheck }

// MarshalSize returns the encoded payload size.
func (ReturnRoutabilityCheck) MarshalSize() int { return 0 }

// MarshalData returns the empty RRC extension_data.
func (ReturnRoutabilityCheck) MarshalData() ([]byte, error) { return nil, nil }

// UnmarshalData validates the empty RRC extension_data.
func (*ReturnRoutabilityCheck) UnmarshalData(data []byte) error {
	if len(data) != 0 {
		return dtlserrors.ErrLengthMismatch
	}

	return nil
}
