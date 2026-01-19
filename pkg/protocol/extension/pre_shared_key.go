// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"golang.org/x/crypto/cryptobyte"
)

// PreSharedKey implements the PreSharedKey extension in DTLS 1.3.
// See RFC 8446 section 4.2.11. Pre-Shared Key Extension.
type PreSharedKey struct {
	// ClientHello: OfferedPsks
	Identities []PskIdentity
	Binders    []PskBinderEntry
	// ServerHello
	SelectedIdentity uint16
}

type PskIdentity struct {
	Identity            []byte
	ObfuscatedTicketAge uint32
}

type PskBinderEntry []byte

// TypeValue returns the extension TypeValue.
func (p PreSharedKey) TypeValue() TypeValue {
	return PreSharedKeyValue
}

// Marshal encodes the extension.
func (p *PreSharedKey) Marshal() ([]byte, error) {
	var out cryptobyte.Builder
	out.AddUint16(uint16(p.TypeValue()))

	// ServerHello
	if len(p.Identities) == 0 || len(p.Binders) == 0 {
		out.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(p.SelectedIdentity)
		})

		return out.Bytes()
	}

	// ClientHello
	out.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, pskIdentity := range p.Identities {
				if len(pskIdentity.Identity) == 0 {
					b.SetError(errPreSharedKeyFormat)
				}
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(pskIdentity.Identity)
				})
				b.AddUint32(pskIdentity.ObfuscatedTicketAge)
			}
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, binder := range p.Binders {
				if len(binder) < 32 {
					b.SetError(errPreSharedKeyFormat)
				}
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(binder)
				})
			}
		})
	})

	return out.Bytes()
}

// Unmarshal populates the extension from encoded data.
func (p *PreSharedKey) Unmarshal(data []byte) error { //nolint:cyclop
	val := cryptobyte.String(data)
	var extension uint16
	if !val.ReadUint16(&extension) || TypeValue(extension) != p.TypeValue() {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errBufferTooSmall
	}

	// ServerHello
	if len(extData) == 2 {
		var selected uint16
		if !extData.ReadUint16(&selected) {
			return errPreSharedKeyFormat
		}
		p.SelectedIdentity = selected

		return nil
	}

	// ClientHello
	var identities cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&identities) || identities.Empty() {
		return errPreSharedKeyFormat
	}

	for !identities.Empty() {
		var identity cryptobyte.String
		var ticket uint32
		if !identities.ReadUint16LengthPrefixed(&identity) || !identities.ReadUint32(&ticket) || identity.Empty() {
			return errPreSharedKeyFormat
		}
		p.Identities = append(p.Identities, PskIdentity{identity, ticket})
	}

	var binders cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&binders) || binders.Empty() {
		return errPreSharedKeyFormat
	}

	for !binders.Empty() {
		var binder cryptobyte.String
		if !binders.ReadUint8LengthPrefixed(&binder) || len(binder) < 32 {
			return errPreSharedKeyFormat
		}
		p.Binders = append(p.Binders, PskBinderEntry(binder))
	}

	return nil
}
