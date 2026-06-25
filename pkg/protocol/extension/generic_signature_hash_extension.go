// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package extension implements the extension values in the ClientHello/ServerHello
package extension

import (
	"crypto/tls"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"golang.org/x/crypto/cryptobyte"
)

// marshalGenericSignatureHashAlgorithm encodes the extension.
// This supports hybrid encoding: TLS 1.3 PSS schemes are encoded as full uint16,
// while TLS 1.2 schemes use hash (high byte) + signature (low byte) encoding.
func marshalGenericSignatureHashAlgorithm(typeValue TypeValue, sigHashAlgs []signaturehash.Algorithm) ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddUint16(uint16(typeValue))
	builder.AddUint16LengthPrefixed(func(extBuilder *cryptobyte.Builder) {
		extBuilder.AddUint16LengthPrefixed(func(algBuilder *cryptobyte.Builder) {
			for _, v := range sigHashAlgs {
				algBuilder.AddBytes(v.Marshal())
			}
		})
	})

	return builder.Bytes()
}

// unmarshalGenericSignatureAlgorithm populates the extension from encoded data.
// This supports hybrid encoding: detects TLS 1.3 PSS schemes
// and handles them as full uint16, while TLS 1.2 schemes use byte-split encoding.
func unmarshalGenericSignatureHashAlgorithm(typeValue TypeValue, data []byte, dst *[]signaturehash.Algorithm) error {
	val := cryptobyte.String(data)
	var extension uint16
	if !val.ReadUint16(&extension) || TypeValue(extension) != typeValue {
		return dtlserrors.ErrInvalidExtensionType
	}

	var extData cryptobyte.String
	if !val.ReadUint16LengthPrefixed(&extData) {
		return dtlserrors.ErrBufferTooSmall
	}

	var algData cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&algData) || !extData.Empty() {
		return dtlserrors.ErrLengthMismatch
	}

	for !algData.Empty() {
		var scheme uint16
		if !algData.ReadUint16(&scheme) {
			return dtlserrors.ErrLengthMismatch
		}

		var alg signaturehash.Algorithm
		err := alg.Unmarshal(tls.SignatureScheme(scheme))
		if err == nil {
			*dst = append(*dst, alg)
		}
	}

	return nil
}
