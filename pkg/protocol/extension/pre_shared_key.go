// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"golang.org/x/crypto/cryptobyte"
)

// PreSharedKey represents the "pre_shared_key" extension for DTLS 1.3.
// This extension is used in both ClientHello and ServerHello messages,
// but only the relevant fields should be populated for each context.
// See RFC 8446 section 4.2.11.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
type PreSharedKey struct {
	// ClientHello only - offered PSK identities
	Identities []PskIdentity
	// ClientHello only - binder values associated with a PSK identity
	Binders []PskBinderEntry
	// ServerHello only - index of selected identity
	SelectedIdentity uint16
}

// PskIdentity represents the PSK identitiy in the "pre_shared_key" extension
// for DTLS 1.3.
type PskIdentity struct {
	Identity            []byte
	ObfuscatedTicketAge uint32
}

// PskBinderEntry represents the binder related to a PSK identity in the
// "pre_shared_key" extension for DTLS 1.3.
type PskBinderEntry []byte

const minPSKBinderSize = 32

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
					b.SetError(dtlserrors.ErrPreSharedKeyFormat)
				}
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(pskIdentity.Identity)
				})
				b.AddUint32(pskIdentity.ObfuscatedTicketAge)
			}
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, binder := range p.Binders {
				if len(binder) < minPSKBinderSize {
					b.SetError(dtlserrors.ErrPreSharedKeyFormat)
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
	payload, err := extensionPayload(data, p.TypeValue())
	if err != nil {
		return err
	}

	return p.unmarshalPayload(payload)
}

func (p *PreSharedKey) unmarshalPayload(data []byte) error { //nolint:cyclop
	extData := cryptobyte.String(data)

	// ServerHello
	if len(extData) == 2 {
		var selected uint16
		if !extData.ReadUint16(&selected) {
			return dtlserrors.ErrPreSharedKeyFormat
		}
		p.SelectedIdentity = selected

		return nil
	}

	// ClientHello
	var identities cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&identities) || identities.Empty() {
		return dtlserrors.ErrPreSharedKeyFormat
	}

	for !identities.Empty() {
		var identity cryptobyte.String
		var ticket uint32
		if !identities.ReadUint16LengthPrefixed(&identity) || !identities.ReadUint32(&ticket) || identity.Empty() {
			return dtlserrors.ErrPreSharedKeyFormat
		}
		p.Identities = append(p.Identities, PskIdentity{identity, ticket})
	}

	var binders cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&binders) || binders.Empty() {
		return dtlserrors.ErrPreSharedKeyFormat
	}

	for !binders.Empty() {
		var binder cryptobyte.String
		if !binders.ReadUint8LengthPrefixed(&binder) || len(binder) < minPSKBinderSize {
			return dtlserrors.ErrPreSharedKeyFormat
		}
		p.Binders = append(p.Binders, PskBinderEntry(binder))
	}

	if !extData.Empty() {
		return dtlserrors.ErrLengthMismatch
	}

	// Ensure there is one binder value per identity in list
	if len(p.Binders) != len(p.Identities) {
		return dtlserrors.ErrPreSharedKeyFormat
	}

	return nil
}
