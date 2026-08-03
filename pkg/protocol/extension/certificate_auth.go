// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"slices"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"golang.org/x/crypto/cryptobyte"
)

// CertificateAuthorities implements the certificate_authorities extension in DTLS 1.3.
//
// See RFC 8446 section 4.2.4. Certificate Authorities.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.4
type CertificateAuthorities struct {
	Authorities [][]byte
}

// TypeValue returns the extension TypeValue.
func (c CertificateAuthorities) TypeValue() TypeValue {
	return CertificateAuthoritiesTypeValue
}

// Marshal encodes the extension.
func (c *CertificateAuthorities) Marshal() ([]byte, error) {
	if len(c.Authorities) == 0 {
		return []byte{}, dtlserrors.ErrInvalidCertificateAuthFormat
	}
	var out cryptobyte.Builder
	out.AddUint16(uint16(c.TypeValue()))
	out.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, ca := range c.Authorities {
				if len(ca) == 0 {
					b.SetError(dtlserrors.ErrInvalidCertificateAuthFormat)

					return
				}
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(ca)
				})
			}
		})
	})

	return out.Bytes()
}

// Unmarshal populates the extension from encoded data.
func (c *CertificateAuthorities) Unmarshal(data []byte) error {
	payload, err := extensionPayload(data, c.TypeValue())
	if err != nil {
		return err
	}

	return c.unmarshalPayload(payload)
}

func (c *CertificateAuthorities) unmarshalPayload(data []byte) error {
	extData := cryptobyte.String(data)

	var auths cryptobyte.String
	if extData.Empty() || !extData.ReadUint16LengthPrefixed(&auths) || auths.Empty() {
		return dtlserrors.ErrInvalidCertificateAuthFormat
	}

	if !extData.Empty() {
		return dtlserrors.ErrLengthMismatch
	}

	var cauths [][]byte
	for !auths.Empty() {
		var ca cryptobyte.String
		if !auths.ReadUint16LengthPrefixed(&ca) || len(ca) == 0 {
			return dtlserrors.ErrInvalidCertificateAuthFormat
		}
		cauths = append(cauths, ca)
	}

	c.Authorities = slices.Clone(cauths)

	return nil
}
