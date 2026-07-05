// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"golang.org/x/crypto/cryptobyte"
)

// EarlyDataIndication implements the early data indication extension in DTLS 1.3.
// See RFC 8446 section 4.2.10. Early Data Indication.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.10
type EarlyDataIndication struct {
	MaxEarlyData *uint32 // nil indicates CH or EE
}

// TypeValue returns the extension TypeValue.
func (e EarlyDataIndication) TypeValue() TypeValue {
	return EarlyDataIndicationTypeValue
}

// Marshal encodes the extension.
func (e *EarlyDataIndication) Marshal() ([]byte, error) {
	var out cryptobyte.Builder
	out.AddUint16(uint16(e.TypeValue()))

	if e.MaxEarlyData == nil {
		out.AddUint16(0) // zero length

		return out.Bytes()
	}

	// new_session_ticket
	out.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint32(*e.MaxEarlyData)
	})

	return out.Bytes()
}

// Unmarshal populates the extension from encoded data.
func (e *EarlyDataIndication) Unmarshal(data []byte) error {
	payload, err := extensionPayload(data, e.TypeValue())
	if err != nil {
		return err
	}

	return e.unmarshalPayload(payload)
}

func (e *EarlyDataIndication) unmarshalPayload(data []byte) error {
	extData := cryptobyte.String(data)

	// new_session_ticket
	if !extData.Empty() {
		var med uint32
		if !extData.ReadUint32(&med) || !extData.Empty() {
			return dtlserrors.ErrEarlyDataIndicationFormat
		}
		e.MaxEarlyData = &med
	}

	return nil
}
