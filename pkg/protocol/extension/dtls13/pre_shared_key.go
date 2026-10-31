// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"bytes"
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	"golang.org/x/crypto/cryptobyte"
)

const minPSKBinderSize = 32

// PSKIdentity identifies a pre-shared key offered by the client.
type PSKIdentity struct {
	Identity            []byte
	ObfuscatedTicketAge uint32
}

// PSKBinder is the binder associated with a PSK identity.
type PSKBinder []byte

// OfferedPSKs is the ClientHello pre_shared_key payload.
type OfferedPSKs struct {
	Identities []PSKIdentity
	Binders    []PSKBinder
}

// ExtensionType returns the IANA extension type.
func (OfferedPSKs) ExtensionType() extension.Type { return extension.TypePreSharedKey }

// MarshalSize returns the encoded payload size without serializing it.
func (o OfferedPSKs) MarshalSize() int {
	total := 4
	for _, identity := range o.Identities {
		total += 6 + len(identity.Identity)
	}
	for _, binder := range o.Binders {
		total += 1 + len(binder)
	}

	return total
}

// MarshalData encodes extension_data.
func (o OfferedPSKs) MarshalData() ([]byte, error) {
	if len(o.Identities) == 0 || len(o.Identities) != len(o.Binders) {
		return nil, dtlserrors.ErrPreSharedKeyFormat
	}

	identities, err := marshalPSKIdentities(o.Identities)
	if err != nil {
		return nil, err
	}

	binders := make([]byte, 0)
	for _, binder := range o.Binders {
		if len(binder) < minPSKBinderSize || len(binder) > 255 || len(binders) > 0xffff-1-len(binder) {
			return nil, dtlserrors.ErrPreSharedKeyFormat
		}
		binders = append(binders, byte(len(binder))) //nolint:gosec // bounded above.
		binders = append(binders, binder...)
	}

	out := make([]byte, 0, 4+len(identities)+len(binders))
	out = binary.BigEndian.AppendUint16(out, uint16(len(identities))) //nolint:gosec // bounded above.
	out = append(out, identities...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(binders))) //nolint:gosec // bounded above.
	out = append(out, binders...)

	return out, nil
}

func marshalPSKIdentities(offered []PSKIdentity) ([]byte, error) {
	identities := make([]byte, 0)
	for _, identity := range offered {
		if len(identity.Identity) == 0 || len(identity.Identity) > 0xffff || len(identities) > 0xffff-6-len(identity.Identity) {
			return nil, dtlserrors.ErrPreSharedKeyFormat
		}
		//nolint:gosec // Identity length is bounded above.
		identities = binary.BigEndian.AppendUint16(identities, uint16(len(identity.Identity)))
		identities = append(identities, identity.Identity...)
		identities = binary.BigEndian.AppendUint32(identities, identity.ObfuscatedTicketAge)
	}

	return identities, nil
}

// UnmarshalData decodes extension_data.
func (o *OfferedPSKs) UnmarshalData(data []byte) error {
	input := cryptobyte.String(data)
	var identitiesData, bindersData cryptobyte.String
	if !input.ReadUint16LengthPrefixed(&identitiesData) || identitiesData.Empty() {
		return dtlserrors.ErrPreSharedKeyFormat
	}
	identities, err := unmarshalPSKIdentities(identitiesData)
	if err != nil {
		return err
	}
	if !input.ReadUint16LengthPrefixed(&bindersData) || bindersData.Empty() || !input.Empty() {
		return dtlserrors.ErrPreSharedKeyFormat
	}
	binders, err := unmarshalPSKBinders(bindersData)
	if err != nil {
		return err
	}
	if len(identities) != len(binders) {
		return dtlserrors.ErrPreSharedKeyFormat
	}
	o.Identities, o.Binders = identities, binders

	return nil
}

func unmarshalPSKIdentities(input cryptobyte.String) ([]PSKIdentity, error) {
	identities := make([]PSKIdentity, 0)
	for !input.Empty() {
		var identity cryptobyte.String
		var age uint32
		if !input.ReadUint16LengthPrefixed(&identity) || identity.Empty() || !input.ReadUint32(&age) {
			return nil, dtlserrors.ErrPreSharedKeyFormat
		}
		identities = append(identities, PSKIdentity{Identity: bytes.Clone(identity), ObfuscatedTicketAge: age})
	}

	return identities, nil
}

func unmarshalPSKBinders(input cryptobyte.String) ([]PSKBinder, error) {
	binders := make([]PSKBinder, 0)
	for !input.Empty() {
		var binder cryptobyte.String
		if !input.ReadUint8LengthPrefixed(&binder) || len(binder) < minPSKBinderSize {
			return nil, dtlserrors.ErrPreSharedKeyFormat
		}
		binders = append(binders, PSKBinder(bytes.Clone(binder)))
	}

	return binders, nil
}

// SelectedPSK is the ServerHello pre_shared_key payload.
type SelectedPSK struct {
	Identity uint16
}

// ExtensionType returns the IANA extension type.
func (SelectedPSK) ExtensionType() extension.Type { return extension.TypePreSharedKey }

// MarshalSize returns the encoded payload size.
func (SelectedPSK) MarshalSize() int { return 2 }

// MarshalData encodes extension_data.
func (s SelectedPSK) MarshalData() ([]byte, error) {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, s.Identity)

	return out, nil
}

// UnmarshalData decodes extension_data.
func (s *SelectedPSK) UnmarshalData(data []byte) error {
	if len(data) != 2 {
		return dtlserrors.ErrPreSharedKeyFormat
	}
	s.Identity = binary.BigEndian.Uint16(data)

	return nil
}
