// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

const (
	supportedSignatureAlgorithmsHeaderSize = 6
)

// SupportedSignatureAlgorithms allows a Client/Server to
// negotiate what SignatureHash Algorithms they both support
//
// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
type SupportedSignatureAlgorithms struct {
	SignatureHashAlgorithms []signaturehash.Algorithm
}

// TypeValue returns the extension TypeValue.
func (s SupportedSignatureAlgorithms) TypeValue() TypeValue {
	return SupportedSignatureAlgorithmsTypeValue
}

// Marshal encodes the extension.
// This supports hybrid encoding: TLS 1.3 PSS schemes are encoded as full uint16,
// while TLS 1.2 schemes use hash (high byte) + signature (low byte) encoding.
func (s *SupportedSignatureAlgorithms) Marshal() ([]byte, error) {
	out := make(
		[]byte,
		// the header size is 6 bytes, each algorithm is a 2-byte identifier.
		supportedSignatureAlgorithmsHeaderSize+2*len(s.SignatureHashAlgorithms),
	)

	binary.BigEndian.PutUint16(out, uint16(s.TypeValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(2+(len(s.SignatureHashAlgorithms)*2))) //nolint:gosec // G115
	binary.BigEndian.PutUint16(out[4:], uint16(len(s.SignatureHashAlgorithms)*2))     //nolint:gosec // G115

	headerEnd := supportedSignatureAlgorithmsHeaderSize
	for i, v := range s.SignatureHashAlgorithms {
		// For PSS schemes, write the full uint16 SignatureScheme value.
		// For other schemes, write hash (high byte) + signature (low byte) in TLS 1.2 style.
		if v.Signature.IsPSS() {
			// TLS 1.3 PSS: full uint16 is the signature scheme
			scheme := uint16(v.Signature)
			out[headerEnd+i*2] = byte(scheme >> 8)
			out[headerEnd+i*2+1] = byte(scheme & 0xFF)
		} else {
			// TLS 1.2 style: hash byte + signature byte
			out[headerEnd+i*2] = byte(v.Hash)
			out[headerEnd+i*2+1] = byte(v.Signature)
		}
	}

	return out, nil
}

// Unmarshal populates the extension from encoded data.
// This supports hybrid encoding: detects TLS 1.3 PSS schemes
// and handles them as full uint16, while TLS 1.2 schemes use byte-split encoding.
func (s *SupportedSignatureAlgorithms) Unmarshal(data []byte) error {
	if len(data) <= supportedSignatureAlgorithmsHeaderSize {
		return errBufferTooSmall
	} else if TypeValue(binary.BigEndian.Uint16(data)) != s.TypeValue() {
		return errInvalidExtensionType
	}

	algorithmCount := int(binary.BigEndian.Uint16(data[4:]) / 2)
	if supportedSignatureAlgorithmsHeaderSize+(algorithmCount*2) > len(data) {
		return errLengthMismatch
	}
	for i := 0; i < algorithmCount; i++ {
		// Read 2 bytes as a uint16 scheme value
		offset := supportedSignatureAlgorithmsHeaderSize + (i * 2)
		scheme := binary.BigEndian.Uint16(data[offset:])

		// Parse the signature scheme (handles both TLS 1.2 and TLS 1.3 PSS encoding)
		supportedHashAlgorithm, supportedSignatureAlgorithm := parseSignatureScheme(scheme, data, offset)

		// Validate both hash and signature algorithms
		if _, ok := hash.Algorithms()[supportedHashAlgorithm]; ok {
			if _, ok := signature.Algorithms()[supportedSignatureAlgorithm]; ok {
				s.SignatureHashAlgorithms = append(s.SignatureHashAlgorithms, signaturehash.Algorithm{
					Hash:      supportedHashAlgorithm,
					Signature: supportedSignatureAlgorithm,
				})
			}
		}
	}

	return nil
}
