// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import dtlserrors "github.com/pion/dtls/v3/internal/errors"

// KeyUpdateRequest indicates whether the recipient should update its sending
// traffic keys as well.
type KeyUpdateRequest uint8

// KeyUpdateRequest values.
const (
	KeyUpdateNotRequested KeyUpdateRequest = iota
	KeyUpdateRequested
)

// MessageKeyUpdate requests an update of DTLS 1.3 application traffic keys.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.3
type MessageKeyUpdate struct {
	RequestUpdate KeyUpdateRequest
}

// Type returns the Handshake Type.
func (m MessageKeyUpdate) Type() Type {
	return TypeKeyUpdate
}

// MarshalSize returns the minimal size required for MarshalTo.
func (m *MessageKeyUpdate) MarshalSize() int {
	return 1
}

// MarshalTo encodes the Handshake into a pre-allocated buffer.
func (m *MessageKeyUpdate) MarshalTo(out []byte) (int, error) {
	if len(out) < 1 {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	if m.RequestUpdate != KeyUpdateNotRequested && m.RequestUpdate != KeyUpdateRequested {
		return 0, dtlserrors.ErrInvalidKeyUpdate
	}
	out[0] = byte(m.RequestUpdate)

	return 1, nil
}

// Marshal encodes the Handshake.
func (m *MessageKeyUpdate) Marshal() ([]byte, error) {
	out := make([]byte, m.MarshalSize())
	_, err := m.MarshalTo(out)

	return out, err
}

// Unmarshal populates the message from encoded data.
func (m *MessageKeyUpdate) Unmarshal(data []byte) error {
	if len(data) != 1 {
		return dtlserrors.ErrLengthMismatch
	}

	requestUpdate := KeyUpdateRequest(data[0])
	if requestUpdate != KeyUpdateNotRequested && requestUpdate != KeyUpdateRequested {
		return dtlserrors.ErrInvalidKeyUpdate
	}
	m.RequestUpdate = requestUpdate

	return nil
}
