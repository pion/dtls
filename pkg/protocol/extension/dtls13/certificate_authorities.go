// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"bytes"
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// CertificateAuthorities is the certificate_authorities payload.
type CertificateAuthorities struct {
	Authorities [][]byte
}

// ExtensionType returns the IANA extension type.
func (CertificateAuthorities) ExtensionType() extension.Type {
	return extension.TypeCertificateAuthorities
}

// MarshalData encodes extension_data.
func (c CertificateAuthorities) MarshalData() ([]byte, error) {
	if len(c.Authorities) == 0 {
		return nil, dtlserrors.ErrInvalidCertificateAuthFormat
	}

	authorities := make([]byte, 0)
	for _, authority := range c.Authorities {
		if len(authority) == 0 || len(authority) > 0xffff || len(authorities) > 0xffff-2-len(authority) {
			return nil, dtlserrors.ErrInvalidCertificateAuthFormat
		}
		authorities = binary.BigEndian.AppendUint16(authorities, uint16(len(authority))) //nolint:gosec // bounded above.
		authorities = append(authorities, authority...)
	}

	out := make([]byte, 2, 2+len(authorities))
	binary.BigEndian.PutUint16(out, uint16(len(authorities))) //nolint:gosec // bounded above.
	out = append(out, authorities...)

	return out, nil
}

// UnmarshalData decodes extension_data.
func (c *CertificateAuthorities) UnmarshalData(data []byte) error {
	if len(data) < 2 {
		return dtlserrors.ErrInvalidCertificateAuthFormat
	}
	length := int(binary.BigEndian.Uint16(data))
	data = data[2:]
	if length == 0 || length != len(data) {
		return dtlserrors.ErrInvalidCertificateAuthFormat
	}

	authorities := make([][]byte, 0)
	for len(data) > 0 {
		if len(data) < 2 {
			return dtlserrors.ErrInvalidCertificateAuthFormat
		}
		authorityLen := int(binary.BigEndian.Uint16(data))
		data = data[2:]
		if authorityLen == 0 || authorityLen > len(data) {
			return dtlserrors.ErrInvalidCertificateAuthFormat
		}
		authorities = append(authorities, bytes.Clone(data[:authorityLen]))
		data = data[authorityLen:]
	}

	c.Authorities = authorities

	return nil
}
