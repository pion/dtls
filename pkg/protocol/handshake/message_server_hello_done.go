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
	err := m.MarshalInto(out)

	return out, err
}

// Size returns the size for MarshalInto.
func (m *MessageServerHelloDone) Size() int {
	return 0
}

// MarshalInto encodes the Handshake.
func (m *MessageServerHelloDone) MarshalInto(out []byte) error {
	return nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageServerHelloDone) Unmarshal([]byte) error {
	return nil
}
