// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package dtls13 implements extension payloads specific to DTLS 1.3.
package dtls13

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// OfferedVersions is the ClientHello supported_versions payload.
type OfferedVersions struct {
	Versions []protocol.Version
}

// ExtensionType returns the IANA extension type.
func (OfferedVersions) ExtensionType() extension.Type { return extension.TypeSupportedVersions }

// MarshalSize returns the encoded payload size without serializing it.
func (o OfferedVersions) MarshalSize() int { return 1 + (2 * len(o.Versions)) }

// MarshalData encodes extension_data.
func (o OfferedVersions) MarshalData() ([]byte, error) {
	length := len(o.Versions) * 2
	if length < 2 || length > 254 {
		return nil, dtlserrors.ErrInvalidSupportedVersionsFormat
	}

	out := make([]byte, 1, 1+length)
	out[0] = byte(length) //nolint:gosec // length is bounded above.
	for _, version := range o.Versions {
		out = append(out, version.Major, version.Minor)
	}

	return out, nil
}

// UnmarshalData decodes extension_data without filtering unknown versions.
func (o *OfferedVersions) UnmarshalData(data []byte) error {
	if len(data) < 3 || int(data[0]) != len(data)-1 || data[0]%2 != 0 {
		return dtlserrors.ErrInvalidSupportedVersionsFormat
	}

	o.Versions = o.Versions[:0]
	for offset := 1; offset+1 < len(data); offset += 2 {
		o.Versions = append(o.Versions, protocol.Version{Major: data[offset], Minor: data[offset+1]})
	}

	return nil
}

// SelectedVersion is the ServerHello and HelloRetryRequest
// supported_versions payload.
type SelectedVersion struct {
	Version protocol.Version
}

// ExtensionType returns the IANA extension type.
func (SelectedVersion) ExtensionType() extension.Type { return extension.TypeSupportedVersions }

// MarshalSize returns the encoded payload size.
func (SelectedVersion) MarshalSize() int { return 2 }

// MarshalData encodes extension_data.
func (s SelectedVersion) MarshalData() ([]byte, error) {
	return []byte{s.Version.Major, s.Version.Minor}, nil
}

// UnmarshalData decodes extension_data.
func (s *SelectedVersion) UnmarshalData(data []byte) error {
	if len(data) != 2 {
		return dtlserrors.ErrInvalidSupportedVersionsFormat
	}

	s.Version = protocol.Version{Major: data[0], Minor: data[1]}

	return nil
}
