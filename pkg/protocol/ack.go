// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

import (
	"golang.org/x/crypto/cryptobyte"
)

// ACK is the DTLS 1.3 content type used to acknowledge receipt of
// handshake records.
//
// https://datatracker.ietf.org/doc/html/rfc9147#section-7
type ACK struct {
	// Records is the list of RecordNumbers being acknowledged.
	Records []RecordNumber
}

// RecordNumber identifies a specific DTLS record by its epoch and sequence number.
// The 128-bit value matches the unpacked RecordNumber structure from RFC 9147 Section 4.2.
type RecordNumber struct {
	Epoch          uint64
	SequenceNumber uint64
}

// ContentType returns the content type for ACK records (26).
func (a ACK) ContentType() ContentType {
	return ContentTypeACK
}

// Marshal encodes the ACK message to its wire format.
func (a *ACK) Marshal() ([]byte, error) {
	var out cryptobyte.Builder

	out.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, rec := range a.Records {
			b.AddUint64(rec.Epoch)
			b.AddUint64(rec.SequenceNumber)
		}
	})

	return out.Bytes()
}

// Unmarshal decodes an ACK message from its wire format.
func (a *ACK) Unmarshal(data []byte) error {
	val := cryptobyte.String(data)

	var recordList cryptobyte.String
	if !val.ReadUint16LengthPrefixed(&recordList) || !val.Empty() {
		return errLengthMismatch
	}

	a.Records = make([]RecordNumber, 0)

	for !recordList.Empty() {
		var rec RecordNumber
		if !recordList.ReadUint64(&rec.Epoch) || !recordList.ReadUint64(&rec.SequenceNumber) {
			return errInvalidACK
		}
		a.Records = append(a.Records, rec)
	}

	return nil
}
