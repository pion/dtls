// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"golang.org/x/crypto/cryptobyte"
)

// SignatureAlgorithmsCert allows a Client/Server to indicate which signature algorithms
// may be used in digital signatures for X.509 certificates.
// This is separate from signature_algorithms which applies to handshake signatures.
//
// RFC 8446 Section 4.2.3:
// "TLS 1.2 implementations SHOULD also process this extension.
// If present, the signature_algorithms_cert extension SHALL be treated as being
// equivalent to signature_algorithms for the purposes of certificate chain validation."
//
// https://tools.ietf.org/html/rfc8446#section-4.2.3
type SignatureAlgorithmsCert struct {
	SignatureHashAlgorithms []signaturehash.Algorithm
}

// TypeValue returns the extension TypeValue.
func (s SignatureAlgorithmsCert) TypeValue() TypeValue {
	return SignatureAlgorithmsCertTypeValue
}

// Marshal encodes the extension.
// This supports hybrid encoding: TLS 1.3 PSS schemes are encoded as full uint16,
// while TLS 1.2 schemes use hash (high byte) + signature (low byte) encoding.
func (s *SignatureAlgorithmsCert) Marshal() ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddUint16(uint16(s.TypeValue()))
	builder.AddUint16LengthPrefixed(func(extBuilder *cryptobyte.Builder) {
		extBuilder.AddUint16LengthPrefixed(func(algBuilder *cryptobyte.Builder) {
			for _, v := range s.SignatureHashAlgorithms {
				// For PSS schemes, write the full uint16 SignatureScheme value
				// For other schemes, write hash (high byte) + signature (low byte) in TLS 1.2 style
				if v.Signature.IsPSS() {
					// TLS 1.3 PSS: full uint16 is the signature scheme
					algBuilder.AddUint16(uint16(v.Signature))
				} else {
					// TLS 1.2 style: hash byte + signature byte
					algBuilder.AddUint8(byte(v.Hash))
					algBuilder.AddUint8(byte(v.Signature))
				}
			}
		})
	})

	return builder.Bytes()
}

// Unmarshal populates the extension from encoded data.
// This supports hybrid encoding: detects TLS 1.3 PSS schemes (0x0804-0x080b)
// and handles them as full uint16, while TLS 1.2 schemes use byte-split encoding.
func (s *SignatureAlgorithmsCert) Unmarshal(data []byte) error {
	val := cryptobyte.String(data)
	var extension uint16
	if !val.ReadUint16(&extension) || TypeValue(extension) != s.TypeValue() {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errBufferTooSmall
	}

	var algData cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&algData) {
		return errLengthMismatch
	}

	s.SignatureHashAlgorithms = []signaturehash.Algorithm{}
	for !algData.Empty() {
		var scheme uint16
		if !algData.ReadUint16(&scheme) {
			return errLengthMismatch
		}

		// Parse the signature scheme (handles both TLS 1.2 and TLS 1.3 PSS encoding)
		var supportedHashAlgorithm hash.Algorithm
		var supportedSignatureAlgorithm signature.Algorithm

		if signature.Algorithm(scheme).IsPSS() {
			// TLS 1.3 PSS scheme - full uint16 is the signature algorithm
			supportedHashAlgorithm = hash.ExtractHashFromPSS(scheme)
			supportedSignatureAlgorithm = signature.Algorithm(scheme)
		} else {
			// TLS 1.2 style - split into hash (high byte) and signature (low byte)
			supportedHashAlgorithm = hash.Algorithm(scheme >> 8)
			supportedSignatureAlgorithm = signature.Algorithm(scheme & 0xFF)
		}

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
