// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

// ChangeCipherSpec protocol exists to signal transitions in
// ciphering strategies.  The protocol consists of a single message,
// which is encrypted and compressed under the current (not the pending)
// connection state.  The message consists of a single byte of value 1.
// https://tools.ietf.org/html/rfc5246#section-7.1
type ChangeCipherSpec struct{}

// ContentType returns the ContentType of this content.
func (c ChangeCipherSpec) ContentType() ContentType {
	return ContentTypeChangeCipherSpec
}

// MarshalSize returns the minimal buffer size required for MarshalTo.
func (c ChangeCipherSpec) MarshalSize() int {
	return 1
}

// Marshal encodes the ChangeCipherSpec to binary.
func (c *ChangeCipherSpec) Marshal() ([]byte, error) {
	out := make([]byte, 1)
	_, err := c.MarshalTo(out)

	return out, err
}

// MarshalTo encodes the ChangeCipherSpec to binary into a pre-allocated buffer.
func (c *ChangeCipherSpec) MarshalTo(out []byte) (int, error) {
	if len(out) < c.MarshalSize() {
		return 0, errBufferTooSmall
	}
	out[0] = 0x01

	return 1, nil
}

// Unmarshal populates the ChangeCipherSpec from binary.
func (c *ChangeCipherSpec) Unmarshal(data []byte) error {
	if len(data) == 1 && data[0] == 0x01 {
		return nil
	}

	return errInvalidCipherSpec
}
