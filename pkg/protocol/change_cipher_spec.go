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

// Size returns the minimal buffer size required for MarshalInto.
func (c ChangeCipherSpec) Size() int {
	return 1
}

// Marshal encodes the ChangeCipherSpec to binary.
func (c *ChangeCipherSpec) Marshal() ([]byte, error) {
	out := make([]byte, 1)
	err := c.MarshalInto(out)

	return out, err
}

// MarshalInto encodes the ChangeCipherSpec to binary into a pre-allocated buffer.
func (c *ChangeCipherSpec) MarshalInto(out []byte) error {
	if len(out) < c.Size() {
		return errBufferTooSmall
	}
	out[0] = 0x01

	return nil
}

// Unmarshal populates the ChangeCipherSpec from binary.
func (c *ChangeCipherSpec) Unmarshal(data []byte) error {
	if len(data) == 1 && data[0] == 0x01 {
		return nil
	}

	return errInvalidCipherSpec
}
