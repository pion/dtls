// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

// ApplicationData messages are carried by the record layer and are
// fragmented, compressed, and encrypted based on the current connection
// state.  The messages are treated as transparent data to the record
// layer.
// https://tools.ietf.org/html/rfc5246#section-10
type ApplicationData struct {
	Data []byte
}

// ContentType returns the ContentType of this content.
func (a ApplicationData) ContentType() ContentType {
	return ContentTypeApplicationData
}

// Marshal encodes the ApplicationData to binary.
func (a *ApplicationData) Marshal() ([]byte, error) {
	out := make([]byte, len(a.Data))
	err := a.MarshalInto(out)

	return out, err
}

// MarshalInto encodes the ApplicationData to binary into a pre-allocated buffer.
func (a *ApplicationData) MarshalInto(out []byte) error {
	copy(out, a.Data)

	return nil
}

// Size returns the size required for MarshalInto.
func (a ApplicationData) Size() int {
	return len(a.Data)
}

// Unmarshal populates the ApplicationData from binary.
func (a *ApplicationData) Unmarshal(data []byte) error {
	a.Data = append([]byte{}, data...)

	return nil
}
