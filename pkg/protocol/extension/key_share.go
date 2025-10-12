// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// KeyShareEntry implements RFC 8446 section 4.2.8.
type KeyShareEntry struct {
	Group       NamedGroup
	KeyExchange []byte // 1..2^16-1 bytes
}

// KeyShare represents the "key_share" extension. Only one of these may be valid at a time.
//
// See RFC 8446 section 4.2.8, 4.2.8.1, and 4.2.8.2.
type KeyShare struct {
	ClientShares  []KeyShareEntry // ClientHello
	ServerShare   *KeyShareEntry  // ServerHello
	SelectedGroup *NamedGroup     // HelloRetryRequest
}

func (k KeyShare) TypeValue() TypeValue { return KeyShareTypeValue }

var (
	errInvalidKeyShareFormat = errors.New("invalid key_share format")
	errInvalidKeyShareGroup  = errors.New("invalid key_share group")
	errDuplicateKeyShare     = errors.New("duplicate key_share group")
)

// Marshal encodes the extension for the active context.
func (k *KeyShare) Marshal() ([]byte, error) { //nolint:cyclop
	hasClientShares := k.ClientShares != nil // vector MAY be empty
	hasServerShare := k.ServerShare != nil
	hasHelloRetryRequest := k.SelectedGroup != nil

	// there must be exactly one context.
	if hasTooManyContexts(hasClientShares, hasServerShare, hasHelloRetryRequest) {
		return nil, errInvalidKeyShareFormat
	}

	if hasClientShares {
		seen := map[NamedGroup]struct{}{}
		for _, e := range k.ClientShares {
			if !IsValidNamedGroup(e.Group) {
				return nil, errInvalidKeyShareGroup
			}

			if _, ok := seen[e.Group]; ok {
				return nil, errDuplicateKeyShare
			}

			seen[e.Group] = struct{}{}

			if l := len(e.KeyExchange); l == 0 || l > 0xffff {
				return nil, errInvalidKeyShareFormat
			}
		}
	}

	if hasServerShare {
		if !IsValidNamedGroup(k.ServerShare.Group) {
			return nil, errInvalidKeyShareGroup
		}

		if l := len(k.ServerShare.KeyExchange); l == 0 || l > 0xffff {
			return nil, errInvalidKeyShareFormat
		}
	}

	if hasHelloRetryRequest && !IsValidNamedGroup(*k.SelectedGroup) {
		return nil, errInvalidKeyShareGroup
	}

	var builder cryptobyte.Builder

	builder.AddUint16(uint16(k.TypeValue()))

	builder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		switch {
		case hasHelloRetryRequest:
			// KeyShareHelloRetryRequest { NamedGroup selected_group; }
			b.AddUint16(uint16(*k.SelectedGroup))

		case hasServerShare:
			// KeyShareServerHello { KeyShareEntry server_share; }
			addKeyShareEntry(b, *k.ServerShare)

		default:
			// KeyShareClientHello { KeyShareEntry client_shares<0..2^16-1>; }
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, e := range k.ClientShares {
					addKeyShareEntry(b, e)
				}
			})
		}
	})

	return builder.Bytes()
}

// Unmarshal parses the extension from any of the three legal contexts.
// Unknown/invalid groups are discarded for ClientHello (as with other TLS lists),
// but are rejected for ServerHello/HelloRetryRequest where a single group must be negotiated.
func (k *KeyShare) Unmarshal(data []byte) error { //nolint:cyclop
	val := cryptobyte.String(data)
	var extData cryptobyte.String

	var ext uint16
	if !val.ReadUint16(&ext) || TypeValue(ext) != k.TypeValue() {
		return errInvalidExtensionType
	}
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errBufferTooSmall
	}
	if extData.Empty() {
		return errInvalidKeyShareFormat
	}

	// Try ClientHello first: client_shares is a uint16-length-prefixed vector.
	peek := extData
	var vecLen uint16
	if peek.ReadUint16(&vecLen) && int(vecLen) == len(peek) { //nolint:nestif
		k.ClientShares, k.ServerShare, k.SelectedGroup = k.ClientShares[:0], nil, nil

		seen := map[NamedGroup]struct{}{}
		for !peek.Empty() {
			var entry KeyShareEntry
			var groupU16 uint16
			var raw cryptobyte.String

			if !peek.ReadUint16(&groupU16) || !peek.ReadUint16LengthPrefixed(&raw) {
				return errInvalidKeyShareFormat
			}

			namedGroup := NamedGroup(groupU16)
			if IsValidNamedGroup(namedGroup) {
				// Enforce "no duplicates" (client MUST NOT offer same group twice).
				if _, ok := seen[namedGroup]; ok {
					return errDuplicateKeyShare
				}

				seen[namedGroup] = struct{}{}

				entry.Group = namedGroup
				entry.KeyExchange = append([]byte(nil), raw...)
				k.ClientShares = append(k.ClientShares, entry)
			}
		}

		// consume vector (2 bytes length + vecLen)
		if !extData.Skip(2 + int(vecLen)) {
			return errInvalidKeyShareFormat
		}

		return nil
	}

	// HelloRetryRequest: exactly 2 bytes = selected_group
	if len(extData) == 2 {
		var groupU16 uint16
		if !extData.ReadUint16(&groupU16) {
			return errInvalidKeyShareFormat
		}

		group := NamedGroup(groupU16)
		if !IsValidNamedGroup(group) {
			return errInvalidKeyShareGroup
		}

		k.ClientShares, k.ServerShare, k.SelectedGroup = nil, nil, &group

		return nil
	}

	// ServerHello: exactly one KeyShareEntry and no trailing bytes
	{
		var groupU16 uint16
		var raw cryptobyte.String

		if !extData.ReadUint16(&groupU16) || !extData.ReadUint16LengthPrefixed(&raw) || !extData.Empty() {
			return errInvalidKeyShareFormat
		}

		group := NamedGroup(groupU16)
		if !IsValidNamedGroup(group) {
			return errInvalidKeyShareGroup
		}

		share := KeyShareEntry{Group: group, KeyExchange: append([]byte(nil), raw...)}
		k.ClientShares, k.ServerShare, k.SelectedGroup = nil, &share, nil

		return nil
	}
}

func addKeyShareEntry(b *cryptobyte.Builder, e KeyShareEntry) {
	b.AddUint16(uint16(e.Group))

	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.KeyExchange)
	})
}

// hasTooManyContexts is used in Marshal(). It returns whether the KeyShare struct has more than exactly one context.
func hasTooManyContexts(b ...bool) bool {
	oneContext := false
	for _, v := range b {
		if v {
			if oneContext {
				return true
			}

			oneContext = true
		}
	}

	return false
}
