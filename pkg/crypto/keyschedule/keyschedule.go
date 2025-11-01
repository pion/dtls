// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package keyschedule implements DTLS 1.3's key derivation related functions
package keyschedule

import (
	"crypto/hkdf"
	"errors"
	"hash"

	"golang.org/x/crypto/cryptobyte"
)

var errMissingHashFunction = errors.New("HKDF-Extract expected a non-nil hash function")
var errLabelTooSmall = errors.New("HKDF-Expand-Label expected a label with length >= 7")
var errLabelTooBig = errors.New("HKDF-Expand-Label expected a label with length <= 255")
var errContextTooBig = errors.New("HKDF-Expand-Label expected a context with length <= 255")

const (
	DTLS13prefix = "dtls13" // RFC 9147 section 5.9
)

// HkdfExtract implements RFC 5869 section 2.2.
func HkdfExtract(hash func() hash.Hash, salt, ikm []byte) ([]byte, error) {
	if hash == nil {
		return nil, errMissingHashFunction
	}
	// The order of the ikm and salt arguments are different than the RFC.
	return hkdf.Extract(hash, ikm, salt)
}

// HkdfExpandLabel implements RFC 8446 section 7.1 with RFC 9147 section 5.9's defined DTLS prefix.
func HkdfExpandLabel(hash func() hash.Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := []byte(DTLS13prefix + label)

	if len(fullLabel) < 7 {
		return nil, errLabelTooSmall
	} else if len(fullLabel) > 255 {
		return nil, errLabelTooBig
	}

	if len(context) > 255 {
		return nil, errContextTooBig
	}

	if hash == nil {
		return nil, errMissingHashFunction
	}

	var builder cryptobyte.Builder

	builder.AddUint16(uint16(length))

	builder.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(fullLabel)
	})

	builder.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})

	hkdfLabel, err := builder.Bytes()
	if err != nil {
		return nil, err
	}

	return hkdf.Expand(hash, secret, string(hkdfLabel), length)
}

// DeriveSecret implements RFC 8446 section 7.1.
//
// TranscriptHash is defined in RFC 8446 section 4.4.
func DeriveSecret(hash func() hash.Hash, secret []byte, label string, transcriptHash hash.Hash) ([]byte, error) {
	if hash == nil {
		return nil, errMissingHashFunction
	}
	if transcriptHash == nil {
		transcriptHash = hash()
	}
	return HkdfExpandLabel(hash, secret, label, transcriptHash.Sum(nil), transcriptHash.Size())
}
