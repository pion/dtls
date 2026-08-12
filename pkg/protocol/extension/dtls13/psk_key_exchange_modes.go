// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// PSKKeyExchangeMode is a value in the PskKeyExchangeMode registry.
type PSKKeyExchangeMode uint8

const (
	PSKKE    PSKKeyExchangeMode = 0
	PSKDHEKE PSKKeyExchangeMode = 1
)

// PSKKeyExchangeModes is the ClientHello psk_key_exchange_modes payload.
type PSKKeyExchangeModes struct {
	Modes []PSKKeyExchangeMode
}

// ExtensionType returns the IANA extension type.
func (PSKKeyExchangeModes) ExtensionType() extension.Type {
	return extension.TypePSKKeyExchangeModes
}

// MarshalData encodes extension_data.
func (p PSKKeyExchangeModes) MarshalData() ([]byte, error) {
	if len(p.Modes) == 0 {
		return nil, dtlserrors.ErrNoPskKeyExchangeMode
	}
	if len(p.Modes) > 255 {
		return nil, dtlserrors.ErrPskKeyExchangeModesFormat
	}

	out := make([]byte, 1, 1+len(p.Modes))
	out[0] = byte(len(p.Modes)) //nolint:gosec // length is bounded above.
	for _, mode := range p.Modes {
		out = append(out, byte(mode))
	}

	return out, nil
}

// UnmarshalData decodes extension_data without filtering unknown modes.
func (p *PSKKeyExchangeModes) UnmarshalData(data []byte) error {
	if len(data) < 2 || int(data[0]) != len(data)-1 {
		return dtlserrors.ErrPskKeyExchangeModesFormat
	}

	p.Modes = make([]PSKKeyExchangeMode, len(data)-1)
	for i, mode := range data[1:] {
		p.Modes[i] = PSKKeyExchangeMode(mode)
	}

	return nil
}
