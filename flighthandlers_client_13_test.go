// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rawExtension struct {
	typeValue extension.TypeValue
	raw       []byte
}

func (e rawExtension) Marshal() ([]byte, error) {
	return append([]byte(nil), e.raw...), nil
}

func (e rawExtension) Unmarshal([]byte) error {
	return nil
}

func (e rawExtension) TypeValue() extension.TypeValue {
	return e.typeValue
}

func marshalHelloRetryRequestServerHello(
	t *testing.T,
	cfg *handshakeConfig,
	extensions []extension.Extension,
) []byte {
	t.Helper()

	var hrrRandomFixed [handshake.RandomLength]byte
	copy(hrrRandomFixed[:], handshake.HelloRetryRequestRandom())
	var hrrRandom handshake.Random
	hrrRandom.UnmarshalFixed(hrrRandomFixed)

	return marshalServerHello(t, cfg, hrrRandom, extensions)
}

func marshalServerHello(
	t *testing.T,
	cfg *handshakeConfig,
	random handshake.Random,
	extensions []extension.Extension,
) []byte {
	t.Helper()

	return marshalServerHelloWithSequence(t, cfg, random, extensions, 0)
}

func marshalServerHelloWithSequence(
	t *testing.T,
	cfg *handshakeConfig,
	random handshake.Random,
	extensions []extension.Extension,
	seq uint16,
) []byte {
	t.Helper()

	cipherSuiteID := uint16(cfg.localCipherSuites[0].ID())
	serverHello := &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		Random:            random,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: defaultCompressionMethods()[0],
		Extensions:        extensions,
	}
	rawServerHello, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: seq},
		Message: serverHello,
	}).Marshal()
	require.NoError(t, err)

	return rawServerHello
}

func generateFlight13_1ClientHello(t *testing.T, cfg *handshakeConfig) *handshake.MessageClientHello {
	t.Helper()

	state := &dtlsstate.State{}

	pkts, dtlsAlert, err := flight13_1Generate(nil, &handshakeContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	return clientHello
}

func TestFlight13_1GenerateClientHelloUsesSupportedVersionsVector(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}

	pkts, dtlsAlert, err := flight13_1Generate(nil, &handshakeContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var supportedVersions *extension.SupportedVersions
	for _, ext := range clientHello.Extensions {
		if sv, ok := ext.(*extension.SupportedVersions); ok {
			supportedVersions = sv

			break
		}
	}
	require.NotNil(t, supportedVersions)
	assert.Equal(t, []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)
	assert.False(t, supportedVersions.IsSelectedVersion())
}

func TestFlight13_1GenerateClientHelloIncludesSignatureAlgorithms(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.localCertSignatureSchemes = cfg.localSignatureSchemes[:1]

	clientHello := generateFlight13_1ClientHello(t, cfg)

	var signatureAlgorithms *extension.SupportedSignatureAlgorithms
	var signatureAlgorithmsCert *extension.SignatureAlgorithmsCert
	for _, ext := range clientHello.Extensions {
		switch typed := ext.(type) {
		case *extension.SupportedSignatureAlgorithms:
			signatureAlgorithms = typed
		case *extension.SignatureAlgorithmsCert:
			signatureAlgorithmsCert = typed
		}
	}

	require.NotNil(t, signatureAlgorithms)
	assert.Equal(t, cfg.localSignatureSchemes, signatureAlgorithms.SignatureHashAlgorithms)
	require.NotNil(t, signatureAlgorithmsCert)
	assert.Equal(t, cfg.localCertSignatureSchemes, signatureAlgorithmsCert.SignatureHashAlgorithms)
}

func TestFlight13_1GenerateClientHelloIncludesSupportedGroups(t *testing.T) {
	cfg := testHandshakeConfig13(t)

	clientHello := generateFlight13_1ClientHello(t, cfg)

	var supportedGroups *extension.SupportedEllipticCurves
	for _, ext := range clientHello.Extensions {
		if typed, ok := ext.(*extension.SupportedEllipticCurves); ok {
			supportedGroups = typed

			break
		}
	}

	require.NotNil(t, supportedGroups)
	assert.Equal(t, cfg.ellipticCurves, supportedGroups.EllipticCurves)
}

func TestFlight13_1GenerateRetainsPrivateKeysForAdvertisedShares(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}

	pkts, dtlsAlert, err := flight13_1Generate(nil, &handshakeContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var keyShare *extension.KeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension.KeyShare); ok {
			keyShare = ks

			break
		}
	}
	require.NotNil(t, keyShare)
	require.Len(t, keyShare.ClientShares, len(cfg.ellipticCurves))
	require.Len(t, state.LocalKeyEntries, len(keyShare.ClientShares))
	require.Len(t, state.LocalKeypairs, len(keyShare.ClientShares))

	for _, entry := range keyShare.ClientShares {
		t.Run(entry.Group.String(), func(t *testing.T) {
			localKeypair, ok := state.LocalKeypairs[entry.Group]
			require.True(t, ok)
			require.Equal(t, entry.KeyExchange, localKeypair.PublicKey)

			peerKeypair, err := elliptic.GenerateKeypair(entry.Group)
			require.NoError(t, err)

			localSecret, err := prf.PreMasterSecret(peerKeypair.PublicKey, localKeypair.PrivateKey, entry.Group)
			require.NoError(t, err)

			peerSecret, err := prf.PreMasterSecret(localKeypair.PublicKey, peerKeypair.PrivateKey, entry.Group)
			require.NoError(t, err)

			assert.Equal(t, peerSecret, localSecret)
		})
	}
}

func TestFlight13_1ParseStoresHelloRetryRequestSelectedGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			&extension.SupportedVersions{
				Versions:        []protocol.Version{protocol.Version1_3},
				SelectedVersion: true,
			},
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	state := &dtlsstate.State{}
	cache := newHandshakeCache()
	cache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13_1Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, flight13_3, nextFlight)
	entries := *state.RemoteKeyEntries
	require.Len(t, entries, 1)
	assert.Equal(t, selectedGroup, entries[0].Group)
	assert.Empty(t, entries[0].KeyExchange)
}

func TestFlight13_1ParseRejectsHelloRetryRequestWithoutSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	state := &dtlsstate.State{}
	cache := newHandshakeCache()
	cache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13_1Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrInvalidHelloRetryRequest)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.IllegalParameter, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.Nil(t, state.RemoteKeyEntries)
}

func TestFlight13_1ParseRejectsHelloRetryRequestWithWrongSelectedVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			&extension.SupportedVersions{
				Versions:        []protocol.Version{protocol.Version1_2},
				SelectedVersion: true,
			},
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	state := &dtlsstate.State{}
	cache := newHandshakeCache()
	cache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13_1Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.ProtocolVersion, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.Nil(t, state.RemoteKeyEntries)
}

func TestFlight13_1ParseRejectsHelloRetryRequestWithClientHelloSupportedVersionsEncoding(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			rawExtension{
				typeValue: extension.SupportedVersionsTypeValue,
				raw: []byte{
					0x00, 0x2b, // supported_versions
					0x00, 0x03, // extension_data length
					0x02,       // ClientHello vector length
					0xfe, 0xfc, // DTLS v1.3
				},
			},
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	state := &dtlsstate.State{}
	cache := newHandshakeCache()
	cache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13_1Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrInvalidHelloRetryRequest)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.IllegalParameter, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.Nil(t, state.RemoteKeyEntries)
}

func TestPickVersionFromServerResponseRejectsHelloRetryRequestWithoutSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.minVersion = protocol.Version1_2
	cfg.maxVersion = protocol.Version1_3
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	conn := &Conn{
		handshakeCache:  newHandshakeCache(),
		handshakeConfig: cfg,
	}
	conn.handshakeCache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)

	ok, err := conn.pickVersionFromServerResponse()

	require.ErrorIs(t, err, dtlserrors.ErrInvalidHelloRetryRequest)
	assert.False(t, ok)
	assert.Equal(t, protocol.Version{}, conn.state.LocalVersion)
}

func TestPickVersionFromServerResponseRejectsServerHelloWithClientHelloSupportedVersionsEncoding(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.minVersion = protocol.Version1_2
	cfg.maxVersion = protocol.Version1_3
	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}

	rawServerHello := marshalServerHello(
		t,
		cfg,
		random,
		[]extension.Extension{
			rawExtension{
				typeValue: extension.SupportedVersionsTypeValue,
				raw: []byte{
					0x00, 0x2b, // supported_versions
					0x00, 0x03, // extension_data length
					0x02,       // ClientHello vector length
					0xfe, 0xfc, // DTLS v1.3
				},
			},
		},
	)

	conn := &Conn{
		handshakeCache:  newHandshakeCache(),
		handshakeConfig: cfg,
	}
	conn.handshakeCache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)

	ok, err := conn.pickVersionFromServerResponse()

	require.ErrorIs(t, err, dtlserrors.ErrInvalidServerHello)
	assert.False(t, ok)
	assert.Equal(t, protocol.Version{}, conn.state.LocalVersion)
}

func TestFlight13_3GenerateRejectsWithoutCommonVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	require.NoError(t, state.LocalRandom.Populate())

	pkts, dtlsAlert, err := flight13_3Generate(nil, &handshakeContext13{
		state: state,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrNoCommonProtocolVersion)
	require.Nil(t, dtlsAlert)
	require.Nil(t, pkts)
}

func TestFlight13_3GenerateIncludesCookieAndSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{
		Cookie:         []byte{0x01, 0x02, 0x03, 0x04},
		RemoteVersions: []protocol.Version{protocol.Version1_3},
	}
	require.NoError(t, state.LocalRandom.Populate())

	pkts, dtlsAlert, err := flight13_3Generate(nil, &handshakeContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var supportedVersions *extension.SupportedVersions
	for _, ext := range clientHello.Extensions {
		if sv, ok := ext.(*extension.SupportedVersions); ok {
			supportedVersions = sv

			break
		}
	}
	require.NotNil(t, supportedVersions)
	assert.Equal(t, []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)
	assert.False(t, supportedVersions.IsSelectedVersion())

	var signatureAlgorithms *extension.SupportedSignatureAlgorithms
	for _, ext := range clientHello.Extensions {
		if sigAlgs, ok := ext.(*extension.SupportedSignatureAlgorithms); ok {
			signatureAlgorithms = sigAlgs

			break
		}
	}
	require.NotNil(t, signatureAlgorithms)
	assert.Equal(t, cfg.localSignatureSchemes, signatureAlgorithms.SignatureHashAlgorithms)

	var cookieExt *extension.CookieExt
	for _, ext := range clientHello.Extensions {
		if c, ok := ext.(*extension.CookieExt); ok {
			cookieExt = c

			break
		}
	}
	require.NotNil(t, cookieExt)
	assert.Equal(t, state.Cookie, cookieExt.Cookie)
}

func TestFlight13_3GeneratePrioritizesHelloRetryRequestSelectedGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	originalKeypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	require.NoError(t, err)
	state := &dtlsstate.State{
		RemoteVersions: []protocol.Version{protocol.Version1_3},
		LocalKeyEntries: []extension.KeyShareEntry{
			{Group: originalKeypair.Curve, KeyExchange: originalKeypair.PublicKey},
		},
		RemoteKeyEntries: &[]extension.KeyShareEntry{{Group: selectedGroup}},
	}
	require.NoError(t, state.LocalRandom.Populate())

	pkts, dtlsAlert, err := flight13_3Generate(nil, &handshakeContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var keyShare *extension.KeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension.KeyShare); ok {
			keyShare = ks

			break
		}
	}
	require.NotNil(t, keyShare)
	require.Len(t, keyShare.ClientShares, 2)
	assert.Equal(t, selectedGroup, keyShare.ClientShares[0].Group)
	assert.NotEmpty(t, keyShare.ClientShares[0].KeyExchange)
	assert.Equal(t, elliptic.X25519, keyShare.ClientShares[1].Group)

	selectedKeypair := state.LocalKeypairs[selectedGroup]
	require.NotNil(t, selectedKeypair)
	assert.Equal(t, keyShare.ClientShares[0].KeyExchange, selectedKeypair.PublicKey)
}

func TestFlight13_3GenerateDoesNotRegenerateAlreadyAdvertisedGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.X25519

	keypair, err := elliptic.GenerateKeypair(selectedGroup)
	require.NoError(t, err)
	state := &dtlsstate.State{
		RemoteVersions: []protocol.Version{protocol.Version1_3},
		LocalKeyEntries: []extension.KeyShareEntry{
			{Group: keypair.Curve, KeyExchange: keypair.PublicKey},
		},
		RemoteKeyEntries: &[]extension.KeyShareEntry{{Group: selectedGroup}},
	}
	require.NoError(t, state.LocalRandom.Populate())

	pkts, dtlsAlert, err := flight13_3Generate(nil, &handshakeContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var keyShare *extension.KeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension.KeyShare); ok {
			keyShare = ks

			break
		}
	}
	require.NotNil(t, keyShare)
	require.Len(t, keyShare.ClientShares, 1)
	assert.Equal(t, selectedGroup, keyShare.ClientShares[0].Group)
}

func TestFlight13_3ParseNegotiatesVersionCipherAndKeyShare(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	_, _, err := flight13_1Generate(nil, &handshakeContext13{state: state, cfg: cfg})
	require.NoError(t, err)

	group := cfg.ellipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01, 0x02, 0x03}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})

	cache := newHandshakeCache()
	cache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)
	nextFlight, dtlsAlert, err := flight13_3Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, flight13_5, nextFlight)

	assert.Equal(t, protocol.Version1_3, state.LocalVersion)
	assert.Equal(t, []protocol.Version{protocol.Version1_3}, state.RemoteVersions)
	require.NotNil(t, state.CipherSuite)
	assert.Equal(t, cfg.localCipherSuites[0].ID(), state.CipherSuite.ID())
	assert.Equal(t, group, state.NamedCurve)
	assert.Equal(t, random.RandomBytes, state.RemoteRandom.RandomBytes)
	require.NotNil(t, state.RemoteKeyEntries)
	require.Len(t, *state.RemoteKeyEntries, 1)
	assert.Equal(t, group, (*state.RemoteKeyEntries)[0].Group)

	clientKeypair := state.LocalKeypairs[group]
	require.NotNil(t, clientKeypair)
	expected, err := prf.PreMasterSecret(clientKeypair.PublicKey, serverKeypair.PrivateKey, group)
	require.NoError(t, err)
	assert.Equal(t, expected, state.PreMasterSecret)
	assert.NotEmpty(t, state.PreMasterSecret)
}

func TestFlight13ClientParseAppendsNoHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	transcript := newHandshakeTranscript13()

	pkts, dtlsAlert, err := flight13_1Generate(nil, &handshakeContext13{
		state:      state,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	appended, err := appendClientHelloInitialFlights13(transcript, pkts)
	require.NoError(t, err)
	require.True(t, appended)
	clientHelloCanonical := canonicalPacketHandshake13(t, pkts[0])

	group := cfg.ellipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)
	rawServerHello := marshalServerHello(t, cfg, handshake.Random{
		RandomBytes: [handshake.RandomBytesLength]byte{0x01},
	}, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})
	serverHelloCanonical, err := canonicalHandshake13(rawServerHello)
	require.NoError(t, err)

	cache := newHandshakeCache()
	cache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)
	nextFlight, dtlsAlert, err := flight13_1Parse(context.Background(), nil, &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, flight13_5, nextFlight)
	assert.Equal(t, []transcriptMessage13{
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 0}, typ: handshake.TypeClientHello},
		{id: transcriptMessageID13{sender: transcriptServer13, seq: 0}, typ: handshake.TypeServerHello},
	}, transcript.order)
	assert.Equal(t, append(append([]byte(nil), clientHelloCanonical...), serverHelloCanonical...), transcript.transcript)
}

func TestFlight13ClientParseAppendsHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	transcript := newHandshakeTranscript13()

	pkts, dtlsAlert, err := flight13_1Generate(nil, &handshakeContext13{
		state:      state,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	appended, err := appendClientHelloInitialFlights13(transcript, pkts)
	require.NoError(t, err)
	require.True(t, appended)
	clientHello1Canonical := canonicalPacketHandshake13(t, pkts[0])

	group := cfg.ellipticCurves[0]
	rawHelloRetryRequest := marshalHelloRetryRequestServerHello(t, cfg, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{SelectedGroup: &group},
	})
	helloRetryRequestCanonical, err := canonicalHandshake13(rawHelloRetryRequest)
	require.NoError(t, err)

	cache := newHandshakeCache()
	cache.push(rawHelloRetryRequest, cfg.initialEpoch, 0, handshake.TypeServerHello, false)
	nextFlight, dtlsAlert, err := flight13_1Parse(context.Background(), nil, &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, flight13_3, nextFlight)

	clientHello2, dtlsAlert, err := flight13_3Generate(nil, &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, clientHello2, 1)
	clientHello2Handshake, ok := clientHello2[0].record.Content.(*handshake.Handshake)
	require.True(t, ok)
	clientHello2Handshake.Header.MessageSequence = 1
	require.NoError(t, appendOutboundHandshakeFlight13(transcript, true, state.CipherSuite, clientHello2))
	clientHello2Canonical := canonicalPacketHandshake13(t, clientHello2[0])

	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)
	rawServerHello := marshalServerHelloWithSequence(
		t,
		cfg,
		handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x02}},
		[]extension.Extension{
			&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
			&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
		},
		1,
	)
	serverHelloCanonical, err := canonicalHandshake13(rawServerHello)
	require.NoError(t, err)
	cache.push(rawServerHello, cfg.initialEpoch, 1, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err = flight13_3Parse(context.Background(), nil, &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, flight13_5, nextFlight)

	clientHello1Hash := hashTranscript13(clientHello1Canonical)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHello1Hash)
	expectedTranscript := append(append(append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...),
		clientHello2Canonical...), serverHelloCanonical...)
	assert.Equal(t, []transcriptMessage13{
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 0}, typ: handshake.TypeClientHello},
		{id: transcriptMessageID13{sender: transcriptServer13, seq: 0}, typ: handshake.TypeServerHello},
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 1}, typ: handshake.TypeClientHello},
		{id: transcriptMessageID13{sender: transcriptServer13, seq: 1}, typ: handshake.TypeServerHello},
	}, transcript.order)
	assert.Equal(t, expectedTranscript, transcript.transcript)
}

func TestFlight13_3ParseKeepsReadingWithoutServerHello(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}

	nextFlight, dtlsAlert, err := flight13_3Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: newHandshakeCache(),
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Zero(t, nextFlight)
}

func TestFlight13_3ParseRejectsSecondHelloRetryRequest(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	_, _, err := flight13_1Generate(nil, &handshakeContext13{state: state, cfg: cfg})
	require.NoError(t, err)

	rawServerHello := marshalHelloRetryRequestServerHello(t, cfg, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
	})

	cache := newHandshakeCache()
	cache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)
	nextFlight, dtlsAlert, err := flight13_3Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrUnexpectedSecondHelloRetryRequest)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.UnexpectedMessage, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
}

func TestFlight13_3ParseRejectsWrongLegacyVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	_, _, err := flight13_1Generate(nil, &handshakeContext13{state: state, cfg: cfg})
	require.NoError(t, err)

	group := cfg.ellipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	cipherSuiteID := uint16(cfg.localCipherSuites[0].ID())
	serverHello := &handshake.MessageServerHello{
		Version:           protocol.Version1_0,
		Random:            handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: defaultCompressionMethods()[0],
		Extensions: []extension.Extension{
			&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
			&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
		},
	}
	rawServerHello, err := (&handshake.Handshake{Message: serverHello}).Marshal()
	require.NoError(t, err)

	cache := newHandshakeCache()
	cache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)
	nextFlight, dtlsAlert, err := flight13_3Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.ProtocolVersion, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
}

func TestFlight13_3ParseRejectsMissingSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	_, _, err := flight13_1Generate(nil, &handshakeContext13{state: state, cfg: cfg})
	require.NoError(t, err)

	group := cfg.ellipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Extension{
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})

	cache := newHandshakeCache()
	cache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)
	nextFlight, dtlsAlert, err := flight13_3Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.ProtocolVersion, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
}

func TestFlight13_3ParseRejectsMissingKeyShare(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
	_, _, err := flight13_1Generate(nil, &handshakeContext13{state: state, cfg: cfg})
	require.NoError(t, err)

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
	})

	cache := newHandshakeCache()
	cache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)
	nextFlight, dtlsAlert, err := flight13_3Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrServerKeyShareMissing)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.IllegalParameter, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
}

func TestFlight13_3ParseRejectsUnofferedKeyShareGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}

	group := cfg.ellipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})

	cache := newHandshakeCache()
	cache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)
	nextFlight, dtlsAlert, err := flight13_3Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrServerKeyShareUnknownGroup)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.IllegalParameter, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
}
