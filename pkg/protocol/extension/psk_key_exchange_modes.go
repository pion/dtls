// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"golang.org/x/crypto/cryptobyte"
)

// PskKeyExchangeModes implements the PskKeyExchangeModes extension in DTLS 1.3.
// See RFC 8446 section 4.2.9. Pre-Shared Key Exchange Modes.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9
type PskKeyExchangeModes struct {
	KeModes []PskKeyExchangeMode
}

type PskKeyExchangeMode uint8

// TypeValue constants.
const (
	PskKe    PskKeyExchangeMode = 0
	PskDheKe PskKeyExchangeMode = 1
)

// TypeValue returns the extension TypeValue.
func (p PskKeyExchangeModes) TypeValue() TypeValue {
	return PskKeyExchangeModesTypeValue
}

// Marshal encodes the extension.
func (p *PskKeyExchangeModes) Marshal() ([]byte, error) {
	if len(p.KeModes) == 0 {
		return nil, dtlserrors.ErrNoPskKeyExchangeMode
	}

	var out cryptobyte.Builder
	out.AddUint16(uint16(p.TypeValue()))

	out.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, keM := range p.KeModes {
				b.AddUint8(uint8(keM))
			}
		})
	})

	return out.Bytes()
}

// Unmarshal populates the extension from encoded data.
func (p *PskKeyExchangeModes) Unmarshal(data []byte) error { //nolint:cyclop
	payload, err := extensionPayload(data, p.TypeValue())
	if err != nil {
		return err
	}

	return p.unmarshalPayload(payload)
}

func (p *PskKeyExchangeModes) unmarshalPayload(data []byte) error { //nolint:cyclop
	extData := cryptobyte.String(data)

	var strModes cryptobyte.String

	if !extData.ReadUint8LengthPrefixed(&strModes) || strModes.Empty() {
		return dtlserrors.ErrPskKeyExchangeModesFormat
	}

	if !extData.Empty() {
		return dtlserrors.ErrLengthMismatch
	}

	p.KeModes = make([]PskKeyExchangeMode, 0)

	for _, mode := range strModes {
		p.KeModes = append(p.KeModes, PskKeyExchangeMode(mode))
	}

	return nil
}
