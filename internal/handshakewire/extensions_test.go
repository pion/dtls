// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshakewire

import (
	"fmt"
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls12"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeExtensionListPreservesRawExtensions(t *testing.T) {
	rawExtensions := []extension.Raw{
		{Type: 0xfefe, Data: []byte{0x01, 0x02}},
		{Type: 0xfefd, Data: []byte{0x03}},
	}
	encoded, err := extension.MarshalRawList(rawExtensions)
	require.NoError(t, err)

	decoded, err := DecodeExtensionList(encoded, ContextClientHello)
	require.NoError(t, err)
	require.Len(t, decoded, 2)
	assert.Equal(t, rawExtensions[0], decoded[0])
	assert.Equal(t, rawExtensions[1], decoded[1])

	roundTrip, err := extension.MarshalList(decoded)
	require.NoError(t, err)
	assert.Equal(t, encoded, roundTrip)
}

func TestDecodeExtensionListUsesMessageContext(t *testing.T) {
	selected := extension13.SelectedVersion{Version: protocol.Version1_3}
	encoded, err := extension.MarshalList([]extension.Value{selected})
	require.NoError(t, err)

	serverHello, err := DecodeExtensionList(encoded, ContextServerHello13)
	require.NoError(t, err)
	require.IsType(t, &extension13.SelectedVersion{}, serverHello[0])

	_, err = DecodeExtensionList(encoded, ContextClientHello)
	assert.Error(t, err)
}

func TestExtensionContextRegistry(t *testing.T) {
	expected := expectedExtensionRegistry()
	require.Len(t, extensionRegistry, len(expected))

	for typ, contexts := range expected {
		registeredContexts, ok := extensionRegistry[typ]
		require.True(t, ok, "missing registry entry for extension %d", typ)
		for _, context := range allExtensionContexts() {
			expectedPayload, expectedAllowed := contexts[context]
			factory, allowed := registeredContexts[context]
			t.Run(fmt.Sprintf("%d/%s", typ, context), func(t *testing.T) {
				assert.Equal(t, expectedAllowed, allowed)
				if !expectedAllowed {
					_, err := DecodeRawExtensions([]extension.Raw{{Type: typ}}, context)
					assert.ErrorIs(t, err, dtlserrors.ErrExtensionNotAllowed)
					assertExtensionAlert(t, err, alert.IllegalParameter)

					return
				}
				if expectedPayload == nil {
					assert.Nil(t, factory)

					return
				}
				require.NotNil(t, factory)
				assert.IsType(t, expectedPayload, factory())
			})
		}
	}
}

func TestUnknownExtensionPreservedByContext(t *testing.T) {
	const unknownType extension.Type = 0xfefe
	for _, context := range allExtensionContexts() {
		t.Run(context.String(), func(t *testing.T) {
			raw := []extension.Raw{{Type: unknownType, Data: []byte{0x01, 0x02}}}
			if context == ContextCertificateRequest {
				raw = append(raw, rawExtensionValue(t, &extension.SignatureAlgorithms{Schemes: []uint16{0x0403}}))
			} else if context == ContextHelloRetryRequest {
				raw = append(raw, rawExtensionValue(t, &extension13.SelectedVersion{Version: protocol.Version1_3}))
			}

			decoded, err := DecodeRawExtensions(raw, context)
			require.NoError(t, err)
			unknown, ok := decoded[0].(extension.Raw)
			require.True(t, ok)
			assert.Equal(t, raw[0], unknown)

			raw[0].Data[0] = 0xff
			assert.Equal(t, []byte{0x01, 0x02}, unknown.Data)
		})
	}
}

func TestServerNameIsNotAllowedInOrdinaryCertificateRequest(t *testing.T) {
	_, err := DecodeRawExtensions([]extension.Raw{{Type: extension.TypeServerName}, rawExtensionValue(t, &extension.SignatureAlgorithms{Schemes: []uint16{0x0403}})}, ContextCertificateRequest)
	assert.ErrorIs(t, err, dtlserrors.ErrExtensionNotAllowed)
	assertExtensionAlert(t, err, alert.IllegalParameter)
}

func TestExtensionBlockRejectsDuplicateTypes(t *testing.T) {
	types := make([]extension.Type, 0, len(extensionRegistry)+1)
	for typ := range extensionRegistry {
		types = append(types, typ)
	}
	types = append(types, 0xfefe)

	for _, typ := range types {
		t.Run(fmt.Sprintf("%d", typ), func(t *testing.T) {
			_, err := DecodeRawExtensions([]extension.Raw{{Type: typ}, {Type: typ}}, ContextClientHello)
			assert.ErrorIs(t, err, dtlserrors.ErrDuplicateExtension)
			assertExtensionAlert(t, err, alert.IllegalParameter)
		})
	}
}

func TestExtensionBlockOrderingAndDependencies(t *testing.T) {
	psk := rawExtensionValue(t, &extension13.OfferedPSKs{Identities: []extension13.PSKIdentity{{Identity: []byte("identity")}}, Binders: []extension13.PSKBinder{make([]byte, 32)}})
	modes := rawExtensionValue(t, &extension13.PSKKeyExchangeModes{Modes: []extension13.PSKKeyExchangeMode{extension13.PSKDHEKE}})

	t.Run("pre shared key is last", func(t *testing.T) {
		_, err := DecodeRawExtensions([]extension.Raw{modes, psk}, ContextClientHello)
		require.NoError(t, err)

		_, err = DecodeRawExtensions([]extension.Raw{psk, modes}, ContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrPreSharedKeyNotLast)
		assertExtensionAlert(t, err, alert.IllegalParameter)
	})

	t.Run("pre shared key requires modes", func(t *testing.T) {
		_, err := DecodeRawExtensions([]extension.Raw{psk}, ContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrMissingPSKKeyExchangeModesExtension)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})

	t.Run("return routability check requires connection ID", func(t *testing.T) {
		rrc := rawExtensionValue(t, &extension.ReturnRoutabilityCheck{})
		_, err := DecodeRawExtensions([]extension.Raw{rrc}, ContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrMissingConnectionIDExtension)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})

	t.Run("early data requires pre shared key", func(t *testing.T) {
		earlyData := rawExtensionValue(t, &extension13.EarlyData{})
		_, err := DecodeRawExtensions([]extension.Raw{earlyData}, ContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrEarlyDataWithoutPreSharedKey)
		assertExtensionAlert(t, err, alert.IllegalParameter)
	})

	t.Run("key share requires groups", func(t *testing.T) {
		keyShare := rawExtensionValue(t, &extension13.ClientKeyShare{})
		versions := rawExtensionValue(t, &extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}})
		_, err := DecodeRawExtensions([]extension.Raw{versions, keyShare}, ContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrKeyShareWithoutSupportedGroups)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})

	t.Run("groups require key share for DTLS 1.3", func(t *testing.T) {
		versions := rawExtensionValue(t, &extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}})
		groups := rawExtensionValue(t, &extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519}})
		signatures := rawExtensionValue(t, &extension.SignatureAlgorithms{Schemes: []uint16{0x0403}})
		_, err := DecodeRawExtensions([]extension.Raw{versions, groups, signatures}, ContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrSupportedGroupsWithoutKeyShare)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})

	t.Run("DTLS 1.3 without PSK requires certificate auth extensions", func(t *testing.T) {
		versions := rawExtensionValue(t, &extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}})
		_, err := DecodeRawExtensions([]extension.Raw{versions}, ContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrMissingClientHelloExtension)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})

	t.Run("supported groups are unique", func(t *testing.T) {
		groups := rawExtensionValue(t, &extension.SupportedGroups{
			Groups: []elliptic.Curve{elliptic.X25519, elliptic.X25519},
		})
		_, err := DecodeRawExtensions([]extension.Raw{groups}, ContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrDuplicateSupportedGroup)
		assertExtensionAlert(t, err, alert.IllegalParameter)
	})

	t.Run("key share follows offered group order", func(t *testing.T) {
		groups := rawExtensionValue(t, &extension.SupportedGroups{
			Groups: []elliptic.Curve{elliptic.X25519, elliptic.P256},
		})
		wrongOrder := rawExtensionValue(t, &extension13.ClientKeyShare{Shares: []extension13.KeyShareEntry{{Group: elliptic.P256, KeyExchange: []byte{0x01}}, {Group: elliptic.X25519, KeyExchange: []byte{0x02}}}})
		_, err := DecodeRawExtensions([]extension.Raw{groups, wrongOrder}, ContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrKeyShareGroupNotOffered)
		assertExtensionAlert(t, err, alert.IllegalParameter)

		validSubset := rawExtensionValue(t, &extension13.ClientKeyShare{Shares: []extension13.KeyShareEntry{{Group: elliptic.P256, KeyExchange: []byte{0x01}}}})
		_, err = DecodeRawExtensions([]extension.Raw{groups, validSubset}, ContextClientHello)
		require.NoError(t, err)
	})

	t.Run("certificate request requires signature algorithms", func(t *testing.T) {
		_, err := DecodeRawExtensions(nil, ContextCertificateRequest)
		assert.ErrorIs(t, err, dtlserrors.ErrMissingSignatureAlgorithmsExtension)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})

	t.Run("HelloRetryRequest requires supported versions", func(t *testing.T) {
		_, err := DecodeRawExtensions(nil, ContextHelloRetryRequest)
		assert.ErrorIs(t, err, dtlserrors.ErrMissingSupportedVersionsExtension)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})
}

func TestExtensionBlockValidatesPlacementBeforePayload(t *testing.T) {
	_, err := DecodeRawExtensions([]extension.Raw{{Type: extension.TypeALPN, Data: []byte{0x00, 0x00}}, {Type: extension.TypeExtendedMasterSecret}}, ContextEncryptedExtensions)
	assert.ErrorIs(t, err, dtlserrors.ErrExtensionNotAllowed)
	assertExtensionAlert(t, err, alert.IllegalParameter)
}

func TestExtensionErrorClassification(t *testing.T) {
	t.Run("framing", func(t *testing.T) {
		_, err := DecodeExtensionList([]byte{0x00}, ContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)
		assertExtensionAlert(t, err, alert.DecodeError)
	})

	t.Run("payload", func(t *testing.T) {
		_, err := DecodeRawExtensions([]extension.Raw{{Type: extension.TypeALPN, Data: []byte{0x00, 0x00}}}, ContextEncryptedExtensions)
		assert.ErrorIs(t, err, extension.ErrALPNInvalidFormat)
		assertExtensionAlert(t, err, alert.DecodeError)
	})
}

func FuzzDecodeExtensionBlock(f *testing.F) {
	f.Add(uint8(0), []byte{0x00, 0x00})
	f.Add(uint8(4), []byte{0x00, 0x05, 0xfe, 0xfe, 0x00, 0x01, 0x01})

	contexts := allExtensionContexts()
	f.Fuzz(func(t *testing.T, contextID uint8, data []byte) {
		context := contexts[int(contextID)%len(contexts)]
		values, err := DecodeExtensionList(data, context)
		if err != nil {
			return
		}

		canonical, err := extension.MarshalList(values)
		require.NoError(t, err)
		_, err = DecodeExtensionList(canonical, context)
		require.NoError(t, err)
	})
}

func allExtensionContexts() []Context {
	return []Context{ContextClientHello, ContextServerHello12, ContextServerHello13, ContextHelloRetryRequest, ContextEncryptedExtensions, ContextCertificateRequest, ContextCertificateEntry, ContextNewSessionTicket}
}

func expectedExtensionRegistry() map[extension.Type]map[Context]extensionPayloadValue {
	return map[extension.Type]map[Context]extensionPayloadValue{
		extension.TypeServerName:            {ContextClientHello: &extension.ServerNameOffer{}, ContextServerHello12: &extension.ServerNameAck{}, ContextEncryptedExtensions: &extension.ServerNameAck{}},
		extension.TypeSupportedGroups:       {ContextClientHello: &extension.SupportedGroups{}, ContextEncryptedExtensions: &extension.SupportedGroups{}},
		extension.TypeSupportedPointFormats: {ContextClientHello: &extension12.SupportedPointFormats{}, ContextServerHello12: &extension12.SupportedPointFormats{}},
		extension.TypeSignatureAlgorithms:   {ContextClientHello: &extension.SignatureAlgorithms{}, ContextCertificateRequest: &extension.SignatureAlgorithms{}},
		extension.TypeUseSRTP:               {ContextClientHello: &extension.SRTPOffer{}, ContextServerHello12: &extension.SRTPSelection{}, ContextEncryptedExtensions: &extension.SRTPSelection{}},
		extension.TypeALPN:                  {ContextClientHello: &extension.ALPNOffer{}, ContextServerHello12: &extension.ALPNSelection{}, ContextEncryptedExtensions: &extension.ALPNSelection{}},
		extension.TypeExtendedMasterSecret:  {ContextClientHello: &extension12.ExtendedMasterSecret{}, ContextServerHello12: &extension12.ExtendedMasterSecret{}},
		extension.TypePreSharedKey:          {ContextClientHello: &extension13.OfferedPSKs{}, ContextServerHello13: &extension13.SelectedPSK{}},
		extension.TypeEarlyData:             {ContextClientHello: &extension13.EarlyData{}, ContextEncryptedExtensions: &extension13.EarlyData{}, ContextNewSessionTicket: &extension13.MaxEarlyData{}},
		extension.TypeSupportedVersions:     {ContextClientHello: &extension13.OfferedVersions{}, ContextServerHello13: &extension13.SelectedVersion{}, ContextHelloRetryRequest: &extension13.SelectedVersion{}},
		extension.TypeCookie:                {ContextClientHello: &extension13.Cookie{}, ContextHelloRetryRequest: &extension13.Cookie{}},
		extension.TypePSKKeyExchangeModes: {
			ContextClientHello: &extension13.PSKKeyExchangeModes{},
		},
		extension.TypeCertificateAuthorities: {ContextClientHello: &extension13.CertificateAuthorities{}, ContextCertificateRequest: &extension13.CertificateAuthorities{}},
		extension.TypeOIDFilters: {
			ContextCertificateRequest: &extension13.OIDFilters{},
		},
		extension.TypePostHandshakeAuth: {
			ContextClientHello: &extension13.PostHandshakeAuth{},
		},
		extension.TypeSignatureAlgorithmsCert: {ContextClientHello: &extension.CertificateSignatureAlgorithms{}, ContextCertificateRequest: &extension.CertificateSignatureAlgorithms{}},
		extension.TypeKeyShare:                {ContextClientHello: &extension13.ClientKeyShare{}, ContextServerHello13: &extension13.ServerKeyShare{}, ContextHelloRetryRequest: &extension13.RetryKeyShare{}},
		extension.TypeConnectionID:            {ContextClientHello: &extension.ConnectionID{}, ContextServerHello12: &extension.ConnectionID{}, ContextServerHello13: &extension.ConnectionID{}},
		extension.TypeReturnRoutabilityCheck:  {ContextClientHello: &extension.ReturnRoutabilityCheck{}, ContextServerHello12: &extension.ReturnRoutabilityCheck{}, ContextServerHello13: &extension.ReturnRoutabilityCheck{}},
		extension.TypeRenegotiationInfo:       {ContextClientHello: &extension12.RenegotiationInfo{}, ContextServerHello12: &extension12.RenegotiationInfo{}},
	}
}

func rawExtensionValue(t *testing.T, value extension.Value) extension.Raw {
	t.Helper()

	data, err := value.MarshalData()
	require.NoError(t, err)

	return extension.Raw{Type: value.ExtensionType(), Data: data}
}

func assertExtensionAlert(t *testing.T, err error, expected alert.Description) {
	t.Helper()

	var got *alert.Alert
	require.ErrorAs(t, err, &got)
	assert.Equal(t, expected, got.Description)
}
