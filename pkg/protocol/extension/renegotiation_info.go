// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

const (
	renegotiationInfoHeaderSize = 5
)

// RenegotiationInfo allows a Client/Server to
// communicate their renegotation support
//
// https://tools.ietf.org/html/rfc5746
type RenegotiationInfo struct {
	RenegotiatedConnection uint8
}

// TypeValue returns the extension TypeValue.
func (r RenegotiationInfo) TypeValue() TypeValue {
	return RenegotiationInfoTypeValue
}

// Marshal encodes the extension.
func (r *RenegotiationInfo) Marshal() ([]byte, error) {
	out := make([]byte, renegotiationInfoHeaderSize)

	binary.BigEndian.PutUint16(out, uint16(r.TypeValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(1)) // length
	out[4] = r.RenegotiatedConnection

	return out, nil
}

// Unmarshal populates the extension from encoded data.
func (r *RenegotiationInfo) Unmarshal(data []byte) error {
	payload, err := extensionPayload(data, r.TypeValue())
	if err != nil {
		return err
	}

	return r.unmarshalPayload(payload)
}

func (r *RenegotiationInfo) unmarshalPayload(data []byte) error {
	if len(data) != 1 {
		return dtlserrors.ErrLengthMismatch
	}

	r.RenegotiatedConnection = data[0]

	return nil
}
