// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package dtls12 implements extension payloads specific to DTLS 1.2.
package dtls12

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// SupportedPointFormats is the ec_point_formats extension payload.
type SupportedPointFormats struct {
	PointFormats []elliptic.CurvePointFormat
}

// ExtensionType returns the IANA extension type.
func (SupportedPointFormats) ExtensionType() extension.Type {
	return extension.TypeSupportedPointFormats
}

// MarshalData encodes extension_data.
func (s SupportedPointFormats) MarshalData() ([]byte, error) {
	if len(s.PointFormats) > 255 {
		return nil, dtlserrors.ErrPointFormatsTooLarge
	}

	out := make([]byte, 1, 1+len(s.PointFormats))
	out[0] = byte(len(s.PointFormats)) //nolint:gosec // length is bounded above.
	for _, format := range s.PointFormats {
		out = append(out, byte(format))
	}

	return out, nil
}

// UnmarshalData decodes extension_data.
func (s *SupportedPointFormats) UnmarshalData(data []byte) error {
	if len(data) == 0 {
		return dtlserrors.ErrBufferTooSmall
	}
	if int(data[0])+1 != len(data) {
		return dtlserrors.ErrLengthMismatch
	}

	s.PointFormats = s.PointFormats[:0]
	for _, value := range data[1:] {
		format := elliptic.CurvePointFormat(value)
		if format == elliptic.CurvePointFormatUncompressed {
			s.PointFormats = append(s.PointFormats, format)
		}
	}

	return nil
}
