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

var (
	errMissingHashFunction = errors.New("HKDF-Extract expected a non-nil hash function")
	errLabelTooSmall       = errors.New("HKDF-Expand-Label expected a label with length >= 7")
	errLabelTooBig         = errors.New("HKDF-Expand-Label expected a label with length <= 255")
	errContextTooBig       = errors.New("HKDF-Expand-Label expected a context with length <= 255")
	errLengthTooBig        = errors.New("HKDF-Expand-Label expected a length <= 65535")
)

const (
	DTLS13prefix = "dtls13" // RFC 9147 section 5.9
)

// HkdfExtract implements RFC 5869 section 2.2.
func HkdfExtract(hash func() hash.Hash, salt, ikm []byte) ([]byte, error) {
	if hash == nil {
		return nil, errMissingHashFunction
	}
	// Note: Go's hkdf.Extract signature is (hash, ikm, salt),
	// while RFC 5869 specifies HKDF-Extract(salt, IKM)
	return hkdf.Extract(hash, ikm, salt)
}

// HkdfExpandLabel implements RFC 8446 section 7.1 with RFC 9147 section 5.9's defined DTLS prefix.
func HkdfExpandLabel(hash func() hash.Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := []byte(DTLS13prefix + label)

	if hash == nil {
		return nil, errMissingHashFunction
	}

	// RFC 8446 section 7.1
	// opaque label<7..255>
	if len(fullLabel) < 7 {
		return nil, errLabelTooSmall
	} else if len(fullLabel) > 255 {
		return nil, errLabelTooBig
	}

	if len(context) > 255 {
		return nil, errContextTooBig
	}

	var builder cryptobyte.Builder

	// RFC 5869 section 2.3
	// L        length of output keying material in octets
	//          (<= 255*HashLen)
	// https://datatracker.ietf.org/doc/html/rfc5869#section-2.3
	if length > hash().Size()*255 {
		return nil, errLengthTooBig
	}
	builder.AddUint16(uint16(length)) //nolint:gosec

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
