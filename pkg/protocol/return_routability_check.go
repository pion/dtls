// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

import dtlserrors "github.com/pion/dtls/v3/internal/errors"

// ReturnRoutabilityCheckMessageType identifies an RFC 9853 RRC message.
type ReturnRoutabilityCheckMessageType uint8

// Return Routability Check message types (rrc_msg_type).
// https://datatracker.ietf.org/doc/html/rfc9853#section-4
const (
	ReturnRoutabilityCheckPathChallenge ReturnRoutabilityCheckMessageType = iota
	ReturnRoutabilityCheckPathResponse
	ReturnRoutabilityCheckPathDrop
)

// ReturnRoutabilityCheckCookieLength is the wire size of an RRC cookie.
// https://datatracker.ietf.org/doc/html/rfc9853#section-4
const ReturnRoutabilityCheckCookieLength = 8

// ReturnRoutabilityCheck carries an RRC path validation message.
type ReturnRoutabilityCheck struct {
	MessageType ReturnRoutabilityCheckMessageType
	Cookie      [ReturnRoutabilityCheckCookieLength]byte
}

// ContentType returns the RRC content type (27).
func (r ReturnRoutabilityCheck) ContentType() ContentType {
	return ContentTypeReturnRoutabilityCheck
}

// MarshalSize returns the minimal size required for MarshalTo.
func (r *ReturnRoutabilityCheck) MarshalSize() int {
	return 1 + len(r.Cookie)
}

// Marshal encodes to wire format.
func (r *ReturnRoutabilityCheck) Marshal() ([]byte, error) {
	out := make([]byte, r.MarshalSize())
	_, err := r.MarshalTo(out)

	return out, err
}

// MarshalTo encodes to wire format into a pre-allocated buffer.
func (r *ReturnRoutabilityCheck) MarshalTo(out []byte) (int, error) {
	out[0] = byte(r.MessageType)

	return copy(out[1:], r.Cookie[:]), nil
}

// Unmarshal decodes an RRC message.
func (r *ReturnRoutabilityCheck) Unmarshal(data []byte) error {
	if len(data) == 0 {
		return dtlserrors.ErrBufferTooSmall
	}

	r.MessageType = ReturnRoutabilityCheckMessageType(data[0])
	// implementations MUST be able to parse and gracefully ignore messages with an unknown msg_type
	// https://datatracker.ietf.org/doc/html/rfc9853#section-4.2
	if r.MessageType > ReturnRoutabilityCheckPathDrop {
		r.Cookie = [ReturnRoutabilityCheckCookieLength]byte{}

		return nil
	}
	if len(data) != 1+len(r.Cookie) {
		return dtlserrors.ErrLengthMismatch
	}

	copy(r.Cookie[:], data[1:])

	return nil
}
