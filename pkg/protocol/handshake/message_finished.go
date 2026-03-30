// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

// MessageFinished is a DTLS Handshake Message
// this message is the first one protected with the just
// negotiated algorithms, keys, and secrets.  Recipients of Finished
// messages MUST verify that the contents are correct.
//
// https://tools.ietf.org/html/rfc5246#section-7.4.9
type MessageFinished struct {
	VerifyData []byte
}

// Type returns the Handshake Type.
func (m MessageFinished) Type() Type {
	return TypeFinished
}

// Size returns the size required for MarshalInto.
func (m *MessageFinished) Size() int {
	return len(m.VerifyData)
}

// Marshal encodes the Handshake.
func (m *MessageFinished) Marshal() ([]byte, error) {
	out := make([]byte, m.Size())
	err := m.MarshalInto(out)

	return out, err
}

// MarshalInto encodes the Handshake into a pre-allocated buffer.
func (m *MessageFinished) MarshalInto(out []byte) error {
	if len(out) < m.Size() {
		return errBufferTooSmall
	}
	copy(out, m.VerifyData)

	return nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageFinished) Unmarshal(data []byte) error {
	m.VerifyData = append([]byte{}, data...)

	return nil
}
