// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"fmt"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
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

	decoded, err := decodeExtensionList(encoded, extensionContextClientHello)
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

	serverHello, err := decodeExtensionList(encoded, extensionContextServerHello13)
	require.NoError(t, err)
	require.IsType(t, &extension13.SelectedVersion{}, serverHello[0])

	_, err = decodeExtensionList(encoded, extensionContextClientHello)
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
					_, err := decodeRawExtensions([]extension.Raw{{Type: typ}}, context)
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
			if context == extensionContextCertificateRequest {
				raw = append(raw, rawExtensionValue(t, &extension.SignatureAlgorithms{Schemes: []uint16{0x0403}}))
			} else if context == extensionContextHelloRetryRequest {
				raw = append(raw, rawExtensionValue(t, &extension13.SelectedVersion{Version: protocol.Version1_3}))
			}

			decoded, err := decodeRawExtensions(raw, context)
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
	_, err := decodeRawExtensions([]extension.Raw{{Type: extension.TypeServerName}, rawExtensionValue(t, &extension.SignatureAlgorithms{Schemes: []uint16{0x0403}})}, extensionContextCertificateRequest)
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
			_, err := decodeRawExtensions([]extension.Raw{{Type: typ}, {Type: typ}}, extensionContextClientHello)
			assert.ErrorIs(t, err, dtlserrors.ErrDuplicateExtension)
			assertExtensionAlert(t, err, alert.IllegalParameter)
		})
	}
}

func TestExtensionBlockOrderingAndDependencies(t *testing.T) {
	psk := rawExtensionValue(t, &extension13.OfferedPSKs{Identities: []extension13.PSKIdentity{{Identity: []byte("identity")}}, Binders: []extension13.PSKBinder{make([]byte, 32)}})
	modes := rawExtensionValue(t, &extension13.PSKKeyExchangeModes{Modes: []extension13.PSKKeyExchangeMode{extension13.PSKDHEKE}})

	t.Run("pre shared key is last", func(t *testing.T) {
		_, err := decodeRawExtensions([]extension.Raw{modes, psk}, extensionContextClientHello)
		require.NoError(t, err)

		_, err = decodeRawExtensions([]extension.Raw{psk, modes}, extensionContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrPreSharedKeyNotLast)
		assertExtensionAlert(t, err, alert.IllegalParameter)
	})

	t.Run("pre shared key requires modes", func(t *testing.T) {
		_, err := decodeRawExtensions([]extension.Raw{psk}, extensionContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrMissingPSKKeyExchangeModesExtension)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})

	t.Run("return routability check requires connection ID", func(t *testing.T) {
		rrc := rawExtensionValue(t, &extension.ReturnRoutabilityCheck{})
		_, err := decodeRawExtensions([]extension.Raw{rrc}, extensionContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrMissingConnectionIDExtension)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})

	t.Run("early data requires pre shared key", func(t *testing.T) {
		earlyData := rawExtensionValue(t, &extension13.EarlyData{})
		_, err := decodeRawExtensions([]extension.Raw{earlyData}, extensionContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrEarlyDataWithoutPreSharedKey)
		assertExtensionAlert(t, err, alert.IllegalParameter)
	})

	t.Run("key share requires groups", func(t *testing.T) {
		keyShare := rawExtensionValue(t, &extension13.ClientKeyShare{})
		versions := rawExtensionValue(t, &extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}})
		_, err := decodeRawExtensions([]extension.Raw{versions, keyShare}, extensionContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrKeyShareWithoutSupportedGroups)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})

	t.Run("groups require key share for DTLS 1.3", func(t *testing.T) {
		versions := rawExtensionValue(t, &extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}})
		groups := rawExtensionValue(t, &extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519}})
		signatures := rawExtensionValue(t, &extension.SignatureAlgorithms{Schemes: []uint16{0x0403}})
		_, err := decodeRawExtensions([]extension.Raw{versions, groups, signatures}, extensionContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrSupportedGroupsWithoutKeyShare)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})

	t.Run("DTLS 1.3 without PSK requires certificate auth extensions", func(t *testing.T) {
		versions := rawExtensionValue(t, &extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}})
		_, err := decodeRawExtensions([]extension.Raw{versions}, extensionContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrMissingClientHelloExtension)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})

	t.Run("supported groups are unique", func(t *testing.T) {
		groups := rawExtensionValue(t, &extension.SupportedGroups{
			Groups: []elliptic.Curve{elliptic.X25519, elliptic.X25519},
		})
		_, err := decodeRawExtensions([]extension.Raw{groups}, extensionContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrDuplicateSupportedGroup)
		assertExtensionAlert(t, err, alert.IllegalParameter)
	})

	t.Run("key share follows offered group order", func(t *testing.T) {
		groups := rawExtensionValue(t, &extension.SupportedGroups{
			Groups: []elliptic.Curve{elliptic.X25519, elliptic.P256},
		})
		wrongOrder := rawExtensionValue(t, &extension13.ClientKeyShare{Shares: []extension13.KeyShareEntry{{Group: elliptic.P256, KeyExchange: []byte{0x01}}, {Group: elliptic.X25519, KeyExchange: []byte{0x02}}}})
		_, err := decodeRawExtensions([]extension.Raw{groups, wrongOrder}, extensionContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrKeyShareGroupNotOffered)
		assertExtensionAlert(t, err, alert.IllegalParameter)

		validSubset := rawExtensionValue(t, &extension13.ClientKeyShare{Shares: []extension13.KeyShareEntry{{Group: elliptic.P256, KeyExchange: []byte{0x01}}}})
		_, err = decodeRawExtensions([]extension.Raw{groups, validSubset}, extensionContextClientHello)
		require.NoError(t, err)
	})

	t.Run("certificate request requires signature algorithms", func(t *testing.T) {
		_, err := decodeRawExtensions(nil, extensionContextCertificateRequest)
		assert.ErrorIs(t, err, dtlserrors.ErrMissingSignatureAlgorithmsExtension)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})

	t.Run("HelloRetryRequest requires supported versions", func(t *testing.T) {
		_, err := decodeRawExtensions(nil, extensionContextHelloRetryRequest)
		assert.ErrorIs(t, err, dtlserrors.ErrMissingSupportedVersionsExtension)
		assertExtensionAlert(t, err, alert.MissingExtension)
	})
}

func TestExtensionBlockValidatesPlacementBeforePayload(t *testing.T) {
	_, err := decodeRawExtensions([]extension.Raw{{Type: extension.TypeALPN, Data: []byte{0x00, 0x00}}, {Type: extension.TypeExtendedMasterSecret}}, extensionContextEncryptedExtensions)
	assert.ErrorIs(t, err, dtlserrors.ErrExtensionNotAllowed)
	assertExtensionAlert(t, err, alert.IllegalParameter)
}

func TestExtensionErrorClassification(t *testing.T) {
	t.Run("framing", func(t *testing.T) {
		_, err := decodeExtensionList([]byte{0x00}, extensionContextClientHello)
		assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)
		assertExtensionAlert(t, err, alert.DecodeError)
	})

	t.Run("payload", func(t *testing.T) {
		_, err := decodeRawExtensions([]extension.Raw{{Type: extension.TypeALPN, Data: []byte{0x00, 0x00}}}, extensionContextEncryptedExtensions)
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
		values, err := decodeExtensionList(data, context)
		if err != nil {
			return
		}

		canonical, err := extension.MarshalList(values)
		require.NoError(t, err)
		_, err = decodeExtensionList(canonical, context)
		require.NoError(t, err)
	})
}

func allExtensionContexts() []extensionContext {
	return []extensionContext{extensionContextClientHello, extensionContextServerHello12, extensionContextServerHello13, extensionContextHelloRetryRequest, extensionContextEncryptedExtensions, extensionContextCertificateRequest, extensionContextCertificateEntry, extensionContextNewSessionTicket}
}

func expectedExtensionRegistry() map[extension.Type]map[extensionContext]extensionPayloadValue {
	return map[extension.Type]map[extensionContext]extensionPayloadValue{
		extension.TypeServerName:            {extensionContextClientHello: &extension.ServerNameOffer{}, extensionContextServerHello12: &extension.ServerNameAck{}, extensionContextEncryptedExtensions: &extension.ServerNameAck{}},
		extension.TypeSupportedGroups:       {extensionContextClientHello: &extension.SupportedGroups{}, extensionContextEncryptedExtensions: &extension.SupportedGroups{}},
		extension.TypeSupportedPointFormats: {extensionContextClientHello: &extension12.SupportedPointFormats{}, extensionContextServerHello12: &extension12.SupportedPointFormats{}},
		extension.TypeSignatureAlgorithms:   {extensionContextClientHello: &extension.SignatureAlgorithms{}, extensionContextCertificateRequest: &extension.SignatureAlgorithms{}},
		extension.TypeUseSRTP:               {extensionContextClientHello: &extension.SRTPOffer{}, extensionContextServerHello12: &extension.SRTPSelection{}, extensionContextEncryptedExtensions: &extension.SRTPSelection{}},
		extension.TypeALPN:                  {extensionContextClientHello: &extension.ALPNOffer{}, extensionContextServerHello12: &extension.ALPNSelection{}, extensionContextEncryptedExtensions: &extension.ALPNSelection{}},
		extension.TypeExtendedMasterSecret:  {extensionContextClientHello: &extension12.ExtendedMasterSecret{}, extensionContextServerHello12: &extension12.ExtendedMasterSecret{}},
		extension.TypePreSharedKey:          {extensionContextClientHello: &extension13.OfferedPSKs{}, extensionContextServerHello13: &extension13.SelectedPSK{}},
		extension.TypeEarlyData:             {extensionContextClientHello: &extension13.EarlyData{}, extensionContextEncryptedExtensions: &extension13.EarlyData{}, extensionContextNewSessionTicket: &extension13.MaxEarlyData{}},
		extension.TypeSupportedVersions:     {extensionContextClientHello: &extension13.OfferedVersions{}, extensionContextServerHello13: &extension13.SelectedVersion{}, extensionContextHelloRetryRequest: &extension13.SelectedVersion{}},
		extension.TypeCookie:                {extensionContextClientHello: &extension13.Cookie{}, extensionContextHelloRetryRequest: &extension13.Cookie{}},
		extension.TypePSKKeyExchangeModes: {
			extensionContextClientHello: &extension13.PSKKeyExchangeModes{},
		},
		extension.TypeCertificateAuthorities: {extensionContextClientHello: &extension13.CertificateAuthorities{}, extensionContextCertificateRequest: &extension13.CertificateAuthorities{}},
		extension.TypeOIDFilters: {
			extensionContextCertificateRequest: &extension13.OIDFilters{},
		},
		extension.TypePostHandshakeAuth: {
			extensionContextClientHello: &extension13.PostHandshakeAuth{},
		},
		extension.TypeSignatureAlgorithmsCert: {extensionContextClientHello: &extension.CertificateSignatureAlgorithms{}, extensionContextCertificateRequest: &extension.CertificateSignatureAlgorithms{}},
		extension.TypeKeyShare:                {extensionContextClientHello: &extension13.ClientKeyShare{}, extensionContextServerHello13: &extension13.ServerKeyShare{}, extensionContextHelloRetryRequest: &extension13.RetryKeyShare{}},
		extension.TypeConnectionID:            {extensionContextClientHello: &extension.ConnectionID{}, extensionContextServerHello12: &extension.ConnectionID{}, extensionContextServerHello13: &extension.ConnectionID{}},
		extension.TypeReturnRoutabilityCheck:  {extensionContextClientHello: &extension.ReturnRoutabilityCheck{}, extensionContextServerHello12: &extension.ReturnRoutabilityCheck{}, extensionContextServerHello13: &extension.ReturnRoutabilityCheck{}},
		extension.TypeRenegotiationInfo:       {extensionContextClientHello: &extension12.RenegotiationInfo{}, extensionContextServerHello12: &extension12.RenegotiationInfo{}},
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
