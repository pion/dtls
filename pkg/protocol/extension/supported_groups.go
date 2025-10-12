// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// SupportedGroups implements TLS 1.3 "supported_groups" (RFC 8446 section 4.2.7).
type SupportedGroups struct {
	// Ordered by preference, most-preferred first.
	Groups []NamedGroup
}

func (s SupportedGroups) TypeValue() TypeValue { return SupportedGroupsTypeValue }

var errInvalidSupportedGroupsFormat = errors.New("invalid supported_groups format")

// Marshal encodes the extension. Requires at least one group.
func (s *SupportedGroups) Marshal() ([]byte, error) {
	if len(s.Groups) == 0 {
		return nil, errInvalidSupportedGroupsFormat
	}

	// validate the groups according to RFC 8446 section 4.2.7.
	for _, g := range s.Groups {
		if !IsValidNamedGroup(g) {
			return nil, errInvalidSupportedGroupsFormat
		}
	}

	var b cryptobyte.Builder
	b.AddUint16(uint16(s.TypeValue()))

	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		// named_group_list<2..2^16-1>
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, g := range s.Groups {
				b.AddUint16(uint16(g))
			}
		})
	})

	return b.Bytes()
}

// Unmarshal decodes the extension from either ClientHello or EncryptedExtensions.
// Unrecognized/unsupported group codes are ignored.
func (s *SupportedGroups) Unmarshal(data []byte) error { //nolint:cyclop
	val := cryptobyte.String(data)
	var extData cryptobyte.String

	var ext uint16
	if !val.ReadUint16(&ext) || TypeValue(ext) != s.TypeValue() {
		return errInvalidExtensionType
	}
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errBufferTooSmall
	}

	// named_group_list<2..2^16-1>
	var list cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&list) || !extData.Empty() {
		return errInvalidSupportedGroupsFormat
	}

	// Must be at least one uint16 (2 bytes) and an even number of bytes.
	if len(list) < 2 || (len(list)%2) != 0 {
		return errInvalidSupportedGroupsFormat
	}

	s.Groups = s.Groups[:0]
	for !list.Empty() {
		var gcode uint16
		if !list.ReadUint16(&gcode) {
			return errInvalidSupportedGroupsFormat
		}

		namedGroup := NamedGroup(gcode)
		if IsValidNamedGroup(namedGroup) {
			s.Groups = append(s.Groups, namedGroup)
		}
	}

	return nil
}
