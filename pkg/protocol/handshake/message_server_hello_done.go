// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

// MessageServerHelloDone is final non-encrypted message from server
// this communicates server has sent all its handshake messages and next
// should be MessageFinished.
type MessageServerHelloDone struct{}

// Type returns the Handshake Type.
func (m MessageServerHelloDone) Type() Type {
	return TypeServerHelloDone
}

// Marshal encodes the Handshake.
func (m *MessageServerHelloDone) Marshal() ([]byte, error) {
	out := []byte{}
	_, err := m.MarshalTo(out)

	return out, err
}

// MarshalSize returns the size for MarshalTo.
func (m *MessageServerHelloDone) MarshalSize() int {
	return 0
}

// MarshalTo encodes the Handshake.
func (m *MessageServerHelloDone) MarshalTo(out []byte) (int, error) {
	return 0, nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageServerHelloDone) Unmarshal([]byte) error {
	return nil
}
