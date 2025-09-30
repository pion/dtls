// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package prf implements DTLS 1.3's key related functions
package keys_schedule_13

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

var DTLS13hash = sha256.New
var errLabelTooSmall = errors.New("HKDF-Expand-Label expected a label with length >= 7")
var errLabelTooBig = errors.New("HKDF-Expand-Label expected a label with length <= 255")
var errContextTooBig = errors.New("HKDF-Expand-Label expected a context with length <= 255")

const (
	DTLS13prefix = "dtls13" // RFC 9147 section 5.9
)

// hkdfExpandLabel implements RFC 8446 section 7.1 with RFC 9147 section 5.9's defined DTLS prefix.
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	// the prefixed label (RFC 9147 section 5.9)
	fullLabel := []byte(DTLS13prefix + label)

	// is guarding against this reasonable here?
	if len(fullLabel) < 7 {
		return nil, errLabelTooSmall
	} else if len(fullLabel) > 255 {
		return nil, errLabelTooBig
	}

	if len(context) > 255 {
		return nil, errContextTooBig
	}

	var builder cryptobyte.Builder

	// QUESTION: how should we validate the length here?
	// it's passed in from deriveSecret which is the length of the hash.
	// the size of the sha256 hash returns a normal int, but we're
	// supposed to write a uint16 here...

	// The HkdfLabel struct (RFC 8446 section 7.1)
	builder.AddUint16(uint16(length)) // the length (RFC 8446 section 7.1)

	builder.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(fullLabel) // the prefixed label (see top of function)
	})

	builder.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})

	hkdfLabel, _ := builder.Bytes()

	// HKDF-Expand-Label (RFC 9147 section 5.9)
	out := make([]byte, length)
	r := hkdf.Expand(DTLS13hash, secret, hkdfLabel)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}

	return out, nil
}

// deriveSecret implements RFC 8446 section 7.1.
func deriveSecret(secret []byte, label string, transcriptHash []byte) ([]byte, error) {
	return hkdfExpandLabel(secret, label, transcriptHash, DTLS13hash().Size())
}
