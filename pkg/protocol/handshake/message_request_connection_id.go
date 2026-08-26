// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import dtlserrors "github.com/pion/dtls/v3/internal/errors"

// MessageRequestConnectionID requests spare CIDs from a peer.
//
// https://datatracker.ietf.org/doc/html/rfc9147#section-9
type MessageRequestConnectionID struct {
	NumCIDs uint8
}

// Type returns the Handshake Type.
func (m MessageRequestConnectionID) Type() Type {
	return TypeRequestConnectionID
}

// MarshalSize returns the minimal size required for MarshalTo.
func (m *MessageRequestConnectionID) MarshalSize() int {
	return 1
}

// Marshal encodes the Handshake.
func (m *MessageRequestConnectionID) Marshal() ([]byte, error) {
	return []byte{m.NumCIDs}, nil
}

// MarshalTo encodes the Handshake into a pre-allocated buffer.
func (m *MessageRequestConnectionID) MarshalTo(out []byte) (int, error) {
	if len(out) < 1 {
		return 0, dtlserrors.ErrBufferTooSmall
	}
	out[0] = m.NumCIDs

	return 1, nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageRequestConnectionID) Unmarshal(data []byte) error {
	if len(data) != 1 {
		return dtlserrors.ErrLengthMismatch
	}

	m.NumCIDs = data[0]

	return nil
}
