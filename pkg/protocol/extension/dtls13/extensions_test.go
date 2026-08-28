// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtensionPayloadRoundTrips(t *testing.T) {
	binder := make([]byte, minPSKBinderSize)
	tests := []struct {
		name  string
		value extension.Value
		out   interface {
			extension.Value
			extension.PayloadUnmarshaller
		}
	}{
		{
			name: "offered versions preserve unknown",
			value: OfferedVersions{Versions: []protocol.Version{
				protocol.Version1_3,
				{Major: 0xfa, Minor: 0xfa},
			}},
			out: &OfferedVersions{},
		},
		{name: "selected version", value: SelectedVersion{Version: protocol.Version1_3}, out: &SelectedVersion{}},
		{name: "cookie", value: Cookie{Cookie: []byte("cookie")}, out: &Cookie{}},
		{name: "empty client key share", value: ClientKeyShare{Shares: []KeyShareEntry{}}, out: &ClientKeyShare{}},
		{
			name: "client key share preserves unknown group",
			value: ClientKeyShare{Shares: []KeyShareEntry{
				{Group: elliptic.X25519, KeyExchange: []byte{1, 2}},
				{Group: elliptic.Curve(0xfafa), KeyExchange: []byte{3}},
			}},
			out: &ClientKeyShare{},
		},
		{
			name:  "server key share",
			value: ServerKeyShare{Share: KeyShareEntry{Group: elliptic.X25519, KeyExchange: []byte{4, 5}}},
			out:   &ServerKeyShare{},
		},
		{
			name:  "retry key share preserves unknown group",
			value: RetryKeyShare{SelectedGroup: elliptic.Curve(0xfafa)},
			out:   &RetryKeyShare{},
		},
		{
			name: "offered psks",
			value: OfferedPSKs{
				Identities: []PSKIdentity{{Identity: []byte("identity"), ObfuscatedTicketAge: 42}},
				Binders:    []PSKBinder{binder},
			},
			out: &OfferedPSKs{},
		},
		{name: "selected psk zero", value: SelectedPSK{Identity: 0}, out: &SelectedPSK{}},
		{
			name:  "psk modes preserve unknown",
			value: PSKKeyExchangeModes{Modes: []PSKKeyExchangeMode{PSKDHEKE, PSKKeyExchangeMode(0xfa)}},
			out:   &PSKKeyExchangeModes{},
		},
		{name: "early data", value: EarlyData{}, out: &EarlyData{}},
		{name: "max early data", value: MaxEarlyData{Size: 4096}, out: &MaxEarlyData{}},
		{
			name:  "certificate authorities",
			value: CertificateAuthorities{Authorities: [][]byte{[]byte("ca1"), []byte("ca2")}},
			out:   &CertificateAuthorities{},
		},
		{
			name: "oid filters",
			value: OIDFilters{Filters: []OIDFilter{
				{OID: []byte{1, 2, 3}, Values: []byte{4, 5}},
			}},
			out: &OIDFilters{},
		},
		{name: "post handshake auth", value: PostHandshakeAuth{}, out: &PostHandshakeAuth{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := test.value.MarshalData()
			require.NoError(t, err)
			assert.Equal(t, len(data), test.value.MarshalSize())
			require.NoError(t, test.out.UnmarshalData(data))
			roundTrip, err := test.out.MarshalData()
			require.NoError(t, err)
			assert.Equal(t, data, roundTrip)
			assert.Equal(t, len(roundTrip), test.out.MarshalSize())
			assert.Equal(t, test.value.ExtensionType(), test.out.ExtensionType())
		})
	}
}

func TestContextSpecificFormsRejectOtherPayloads(t *testing.T) {
	clientVersions, err := (OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}}).MarshalData()
	require.NoError(t, err)
	assert.ErrorIs(t, (&SelectedVersion{}).UnmarshalData(clientVersions), dtlserrors.ErrInvalidSupportedVersionsFormat)

	serverShare, err := (ServerKeyShare{
		Share: KeyShareEntry{Group: elliptic.X25519, KeyExchange: []byte{1}},
	}).MarshalData()
	require.NoError(t, err)
	assert.ErrorIs(t, (&RetryKeyShare{}).UnmarshalData(serverShare), dtlserrors.ErrInvalidKeyShareFormat)

	selectedPSK, err := (SelectedPSK{Identity: 0}).MarshalData()
	require.NoError(t, err)
	assert.ErrorIs(t, (&OfferedPSKs{}).UnmarshalData(selectedPSK), dtlserrors.ErrPreSharedKeyFormat)

	maxEarlyData, err := (MaxEarlyData{Size: 1}).MarshalData()
	require.NoError(t, err)
	assert.ErrorIs(t, (&EarlyData{}).UnmarshalData(maxEarlyData), dtlserrors.ErrEarlyDataIndicationFormat)
}

func TestKeyShareDuplicateGroup(t *testing.T) {
	_, err := (ClientKeyShare{Shares: []KeyShareEntry{
		{Group: elliptic.X25519, KeyExchange: []byte{1}},
		{Group: elliptic.X25519, KeyExchange: []byte{2}},
	}}).MarshalData()
	assert.ErrorIs(t, err, dtlserrors.ErrDuplicateKeyShare)
}

func TestExtensionPayloadValidation(t *testing.T) {
	t.Run("supported versions", func(t *testing.T) {
		_, err := (OfferedVersions{}).MarshalData()
		assert.ErrorIs(t, err, dtlserrors.ErrInvalidSupportedVersionsFormat)
		assert.ErrorIs(t, (&OfferedVersions{}).UnmarshalData([]byte{3, 0xfe, 0xfc, 0xfe}),
			dtlserrors.ErrInvalidSupportedVersionsFormat)
		assert.ErrorIs(t, (&SelectedVersion{}).UnmarshalData([]byte{0xfe}),
			dtlserrors.ErrInvalidSupportedVersionsFormat)
	})

	t.Run("offered psks", func(t *testing.T) {
		identity := PSKIdentity{Identity: []byte("identity")}
		binder := make(PSKBinder, minPSKBinderSize)

		_, err := (OfferedPSKs{Identities: []PSKIdentity{identity}}).MarshalData()
		assert.ErrorIs(t, err, dtlserrors.ErrPreSharedKeyFormat)
		_, err = (OfferedPSKs{
			Identities: []PSKIdentity{identity},
			Binders:    []PSKBinder{binder[:minPSKBinderSize-1]},
		}).MarshalData()
		assert.ErrorIs(t, err, dtlserrors.ErrPreSharedKeyFormat)
		assert.ErrorIs(t, (&OfferedPSKs{}).UnmarshalData([]byte{0, 6, 0, 0, 0, 0, 0, 0, 0, 0}),
			dtlserrors.ErrPreSharedKeyFormat)
	})

	t.Run("oid filters", func(t *testing.T) {
		_, err := (OIDFilters{Filters: []OIDFilter{{}}}).MarshalData()
		assert.ErrorIs(t, err, dtlserrors.ErrEmptyOIDFilter)
		_, err = (OIDFilters{Filters: []OIDFilter{{OID: []byte{1}}, {OID: []byte{1}}}}).MarshalData()
		assert.ErrorIs(t, err, dtlserrors.ErrDuplicateOID)
		assert.ErrorIs(t, (&OIDFilters{}).UnmarshalData([]byte{0, 8, 1, 1, 0, 0, 1, 1, 0, 0}),
			dtlserrors.ErrDuplicateOID)
	})
}

func FuzzClientKeyShareUnmarshalData(f *testing.F) {
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 5, 0, 29, 0, 1, 1})

	f.Fuzz(func(t *testing.T, data []byte) {
		var value ClientKeyShare
		if err := value.UnmarshalData(data); err != nil {
			return
		}
		encoded, err := value.MarshalData()
		require.NoError(t, err)
		assert.Equal(t, data, encoded)
	})
}

func FuzzPayloadUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 2, 0xfe, 0xfc})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = (&OfferedVersions{}).UnmarshalData(data)
		_ = (&SelectedVersion{}).UnmarshalData(data)
		_ = (&Cookie{}).UnmarshalData(data)
		_ = (&ClientKeyShare{}).UnmarshalData(data)
		_ = (&ServerKeyShare{}).UnmarshalData(data)
		_ = (&RetryKeyShare{}).UnmarshalData(data)
		_ = (&OfferedPSKs{}).UnmarshalData(data)
		_ = (&SelectedPSK{}).UnmarshalData(data)
		_ = (&PSKKeyExchangeModes{}).UnmarshalData(data)
		_ = (&EarlyData{}).UnmarshalData(data)
		_ = (&MaxEarlyData{}).UnmarshalData(data)
		_ = (&CertificateAuthorities{}).UnmarshalData(data)
		_ = (&OIDFilters{}).UnmarshalData(data)
		_ = (&PostHandshakeAuth{}).UnmarshalData(data)
	})
}
