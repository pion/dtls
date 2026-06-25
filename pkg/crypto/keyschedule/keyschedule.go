// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package keyschedule implements DTLS 1.3's key derivation related functions
package keyschedule

import (
	"crypto/hkdf"
	"hash"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"golang.org/x/crypto/cryptobyte"
)

const (
	DTLS13prefix = "dtls13" // RFC 9147 section 5.9
)

// HkdfExtract implements RFC 5869 section 2.2.
func HkdfExtract(hash func() hash.Hash, salt, ikm []byte) ([]byte, error) {
	if hash == nil {
		return nil, dtlserrors.ErrKeyScheduleMissingHashFunction
	}
	// Note: Go's hkdf.Extract signature is (hash, ikm, salt),
	// while RFC 5869 specifies HKDF-Extract(salt, IKM)
	return hkdf.Extract(hash, ikm, salt)
}

// HkdfExpandLabel implements RFC 8446 section 7.1 with RFC 9147 section 5.9's defined DTLS prefix.
func HkdfExpandLabel(hash func() hash.Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := []byte(DTLS13prefix + label)

	if hash == nil {
		return nil, dtlserrors.ErrKeyScheduleMissingHashFunction
	}

	// RFC 8446 section 7.1
	// opaque label<7..255>
	if len(fullLabel) < 7 {
		return nil, dtlserrors.ErrKeyScheduleLabelTooSmall
	} else if len(fullLabel) > 255 {
		return nil, dtlserrors.ErrKeyScheduleLabelTooBig
	}

	if len(context) > 255 {
		return nil, dtlserrors.ErrKeyScheduleContextTooBig
	}

	var builder cryptobyte.Builder

	// RFC 5869 section 2.3
	// L        length of output keying material in octets
	//          (<= 255*HashLen)
	// https://datatracker.ietf.org/doc/html/rfc5869#section-2.3
	if length > hash().Size()*255 {
		return nil, dtlserrors.ErrKeyScheduleLengthTooBig
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
		return nil, dtlserrors.ErrKeyScheduleMissingHashFunction
	}
	if transcriptHash == nil {
		transcriptHash = hash()
	}

	return HkdfExpandLabel(hash, secret, label, transcriptHash.Sum(nil), transcriptHash.Size())
}
