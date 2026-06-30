// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlight13_0ParseGeneratesKeypairForNegotiatedGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.P384, elliptic.P256}

	clientKeypair, err := elliptic.GenerateKeypair(elliptic.P384)
	require.NoError(t, err)
	staleServerKeypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	require.NoError(t, err)

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: defaultCompressionMethods(),
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
			},
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.P384},
			},
			&extension.KeyShare{
				ClientShares: []extension.KeyShareEntry{
					{Group: elliptic.P384, KeyExchange: clientKeypair.PublicKey},
				},
			},
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
		},
	}
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	require.NoError(t, err)

	state := &dtlsstate.State{
		LocalVersion: protocol.Version1_3,
		NamedCurve:   elliptic.X25519,
		LocalKeypair: staleServerKeypair,
	}
	cache := dtlsflight.NewCache()
	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight2, nextFlight)
	require.NotNil(t, state.LocalKeypair)
	assert.Equal(t, elliptic.P384, state.NamedCurve)
	assert.Equal(t, elliptic.P384, state.LocalKeypair.Curve)
}

func TestFlight13_0ParseRejectsClientHelloWithSelectedSupportedVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: defaultCompressionMethods(),
		Extensions: []extension.Extension{
			&extension.SupportedVersions{
				Versions:        []protocol.Version{protocol.Version1_3},
				SelectedVersion: true,
			},
		},
	}
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	require.NoError(t, err)

	state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.ErrorIs(t, err, dtlserrors.ErrInvalidClientHello)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.IllegalParameter, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.Empty(t, state.RemoteVersions)
}

func pushFlight13_0ClientHello(
	t *testing.T,
	cache *dtlsflight.Cache,
	cfg *handshakeConfig,
	exts []extension.Extension,
) []byte {
	t.Helper()

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: defaultCompressionMethods(),
		Extensions:         exts,
	}
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	require.NoError(t, err)

	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	return rawClientHello
}

func requiredClientHello13Extensions(t *testing.T, cfg *handshakeConfig) []extension.Extension {
	t.Helper()

	clientKeypair, err := elliptic.GenerateKeypair(cfg.EllipticCurves[0])
	require.NoError(t, err)

	return []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
		},
		&extension.SupportedEllipticCurves{
			EllipticCurves: cfg.EllipticCurves,
		},
		&extension.KeyShare{
			ClientShares: []extension.KeyShareEntry{
				{Group: clientKeypair.Curve, KeyExchange: clientKeypair.PublicKey},
			},
		},
		&extension.SupportedVersions{
			Versions: []protocol.Version{protocol.Version1_3},
		},
	}
}

func TestFlight13_0ParseRequiresCertificateAuthClientHelloExtensions(t *testing.T) {
	t.Run("AcceptsSignatureAlgorithmsAndSupportedGroups", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cache := dtlsflight.NewCache()
		pushFlight13_0ClientHello(t, cache, cfg, requiredClientHello13Extensions(t, cfg))

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, dtlsflight13.Flight2, nextFlight)
		assert.Equal(t, cfg.LocalSignatureSchemes, state.RemoteSignatureSchemes)
		assert.Equal(t, cfg.EllipticCurves, state.RemoteGroups)
	})

	t.Run("AllowsPreSharedKeyWithoutCertificateAuthExtensions", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cache := dtlsflight.NewCache()
		binder := make([]byte, 32)
		pushFlight13_0ClientHello(t, cache, cfg, []extension.Extension{
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
			&extension.PreSharedKey{
				Identities: []extension.PskIdentity{
					{Identity: []byte("psk"), ObfuscatedTicketAge: 0},
				},
				Binders: []extension.PskBinderEntry{binder},
			},
		})

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, dtlsflight13.Flight2, nextFlight)
	})

	t.Run("RejectsMissingSignatureAlgorithms", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cache := dtlsflight.NewCache()
		exts := requiredClientHello13Extensions(t, cfg)[1:]
		pushFlight13_0ClientHello(t, cache, cfg, exts)

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.ErrorIs(t, err, dtlserrors.ErrMissingClientHelloExtension)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
		assert.Zero(t, nextFlight)
	})

	t.Run("RejectsSignatureAlgorithmsCertAsSubstitute", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cache := dtlsflight.NewCache()
		exts := requiredClientHello13Extensions(t, cfg)[1:]
		exts = append([]extension.Extension{
			&extension.SignatureAlgorithmsCert{
				SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
			},
		}, exts...)
		pushFlight13_0ClientHello(t, cache, cfg, exts)

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.ErrorIs(t, err, dtlserrors.ErrMissingClientHelloExtension)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
		assert.Zero(t, nextFlight)
	})

	t.Run("RejectsMissingSupportedGroups", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cache := dtlsflight.NewCache()
		required := requiredClientHello13Extensions(t, cfg)
		exts := []extension.Extension{required[0], required[2], required[3]}
		pushFlight13_0ClientHello(t, cache, cfg, exts)

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.ErrorIs(t, err, dtlserrors.ErrMissingClientHelloExtension)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
		assert.Zero(t, nextFlight)
	})
}

func TestFlight13ServerParseAppendsNoHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.InsecureSkipHelloVerify = true
	state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	rawClientHello := pushFlight13_0ClientHello(t, cache, cfg, requiredClientHello13Extensions(t, cfg))
	clientHelloCanonical, err := canonicalHandshake13(rawClientHello)
	require.NoError(t, err)
	transcript := newHandshakeTranscript13()

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight4, nextFlight)
	assert.Equal(t, []transcriptMessage13{
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 0}, typ: handshake.TypeClientHello},
	}, transcript.order)
	assert.Equal(t, clientHelloCanonical, transcript.transcript)
}

func TestFlight13ServerParseAppendsHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cookie := []byte{0xde, 0xad, 0xbe, 0xef}
	state := &dtlsstate.State{
		LocalVersion: protocol.Version1_3,
		Cookie:       cookie,
	}
	cache := dtlsflight.NewCache()
	rawClientHello1 := pushFlight13_0ClientHello(t, cache, cfg, requiredClientHello13Extensions(t, cfg))
	clientHello1Canonical, err := canonicalHandshake13(rawClientHello1)
	require.NoError(t, err)
	transcript := newHandshakeTranscript13()
	flightCtx := &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	}

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight0, context.Background(), flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight2, nextFlight)

	helloRetryRequest, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight2, flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, helloRetryRequest, 1)
	require.NoError(t, appendOutboundHandshakeFlight13(transcript, false, state.CipherSuite, helloRetryRequest))
	helloRetryRequestCanonical := canonicalPacketHandshake13(t, helloRetryRequest[0])

	exts := append(requiredClientHello13Extensions(t, cfg), &extension.CookieExt{Cookie: cookie})
	rawClientHello2 := pushClientHello13WithSequence(t, cache, protocol.Version1_2, 1, exts)
	clientHello2Canonical, err := canonicalHandshake13(rawClientHello2)
	require.NoError(t, err)

	nextFlight, dtlsAlert, err = flight13ParseForTest(t, dtlsflight13.Flight2, context.Background(), flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight4, nextFlight)

	clientHello1Hash := hashTranscript13(clientHello1Canonical)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHello1Hash)
	expectedTranscript := append(append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...),
		clientHello2Canonical...)
	assert.Equal(t, []transcriptMessage13{
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 0}, typ: handshake.TypeClientHello},
		{id: transcriptMessageID13{sender: transcriptServer13, seq: 0}, typ: handshake.TypeServerHello},
		{id: transcriptMessageID13{sender: transcriptClient13, seq: 1}, typ: handshake.TypeClientHello},
	}, transcript.order)
	assert.Equal(t, expectedTranscript, transcript.transcript)
}

func serverHelloFromFlight13_2(
	t *testing.T, state *dtlsstate.State, cfg *handshakeConfig,
) *handshake.MessageServerHello {
	t.Helper()

	if state.CipherSuite == nil {
		state.CipherSuite = cfg.LocalCipherSuites[0]
	}
	pkts, dtlsAlert, err := flight13GenerateForTest(
		t, dtlsflight13.Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
	)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	require.NotNil(t, pkts[0].Record)
	assert.Equal(t, protocol.Version1_2, pkts[0].Record.Header.Version)

	content, ok := pkts[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)

	serverHello, ok := content.Message.(*handshake.MessageServerHello)
	require.True(t, ok)

	return serverHello
}

func findSupportedVersions(exts []extension.Extension) (*extension.SupportedVersions, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension.SupportedVersions); ok {
			return typed, true
		}
	}

	return nil, false
}

func findKeyShare(exts []extension.Extension) (*extension.KeyShare, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension.KeyShare); ok {
			return typed, true
		}
	}

	return nil, false
}

func findCookie(exts []extension.Extension) (*extension.CookieExt, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension.CookieExt); ok {
			return typed, true
		}
	}

	return nil, false
}

func TestFlight13_2Generate(t *testing.T) {
	t.Run("ServerHelloIsHelloRetryRequest", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		assert.Equal(t, protocol.Version1_2, serverHello.Version)
		assert.Equal(t, [32]byte(handshake.HelloRetryRequestRandom()), serverHello.Random.MarshalFixed())
	})

	t.Run("ResetsHandshakeSendSequence", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{
			LocalVersion:          protocol.Version1_3,
			CipherSuite:           cfg.LocalCipherSuites[0],
			HandshakeSendSequence: 7,
		}

		_, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)

		assert.Equal(t, 0, state.HandshakeSendSequence)
	})

	t.Run("RejectsWithoutCipherSuite", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrCipherSuiteUnset)
		require.Nil(t, dtlsAlert)
		require.Nil(t, pkts)
	})

	t.Run("AlwaysIncludesSupportedVersions", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		require.True(t, ok, "SupportedVersions extension must always be present")
		assert.Equal(t, []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)
		assert.True(t, supportedVersions.IsSelectedVersion())
	})

	t.Run("IncludesCipherSuiteAndCompressionMethod", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		require.NotNil(t, serverHello.CipherSuiteID)
		assert.Equal(t, uint16(cfg.LocalCipherSuites[0].ID()), *serverHello.CipherSuiteID)
		require.NotNil(t, serverHello.CompressionMethod)
		assert.Equal(t, defaultCompressionMethods()[0], serverHello.CompressionMethod)

		raw, err := (&handshake.Handshake{Message: serverHello}).Marshal()
		require.NoError(t, err)

		var parsed handshake.Handshake
		require.NoError(t, parsed.Unmarshal(raw))
		parsedServerHello, ok := parsed.Message.(*handshake.MessageServerHello)
		require.True(t, ok)
		require.NotNil(t, parsedServerHello.CipherSuiteID)
		assert.Equal(t, *serverHello.CipherSuiteID, *parsedServerHello.CipherSuiteID)
	})

	t.Run("OmitsKeyShareAndCookieByDefault", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		_, hasKeyShare := findKeyShare(serverHello.Extensions)
		assert.False(t, hasKeyShare, "KeyShare must be omitted when no remote key entries were offered")

		_, hasCookie := findCookie(serverHello.Extensions)
		assert.False(t, hasCookie, "Cookie must be omitted when no cookie is set")

		require.Len(t, serverHello.Extensions, 1)
	})

	t.Run("IncludesKeyShareWhenRemoteKeyEntriesPresent", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, NamedCurve: elliptic.X25519}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		keyShare, ok := findKeyShare(serverHello.Extensions)
		require.True(t, ok, "KeyShare must be present when remote key entries were offered")
		require.NotNil(t, keyShare.SelectedGroup)
		assert.Equal(t, elliptic.X25519, *keyShare.SelectedGroup)
	})

	t.Run("IncludesCookieWhenSet", func(t *testing.T) {
		cookie := []byte{0x01, 0x02, 0x03, 0x04}
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		cookieExt, ok := findCookie(serverHello.Extensions)
		require.True(t, ok, "Cookie must be present when set on state")
		assert.Equal(t, cookie, cookieExt.Cookie)
	})

	t.Run("IncludesAllExtensionsTogether", func(t *testing.T) {
		cookie := []byte{0xaa, 0xbb}
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, NamedCurve: elliptic.P256, Cookie: cookie}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		require.Len(t, serverHello.Extensions, 3)

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		require.True(t, ok)
		assert.Equal(t, supportedVersionsRange(cfg.MinVersion, cfg.MaxVersion), supportedVersions.Versions)

		keyShare, ok := findKeyShare(serverHello.Extensions)
		require.True(t, ok)
		require.NotNil(t, keyShare.SelectedGroup)
		assert.Equal(t, elliptic.P256, *keyShare.SelectedGroup)

		cookieExt, ok := findCookie(serverHello.Extensions)
		require.True(t, ok)
		assert.Equal(t, cookie, cookieExt.Cookie)
	})
}

func pushClientHello13(
	t *testing.T,
	cache *dtlsflight.Cache,
	version protocol.Version,
	exts []extension.Extension,
) {
	t.Helper()

	pushClientHello13WithSequence(t, cache, version, 0, exts)
}

func pushClientHello13WithSequence(
	t *testing.T,
	cache *dtlsflight.Cache,
	version protocol.Version,
	seq uint16,
	exts []extension.Extension,
) []byte {
	t.Helper()

	content := &handshake.Handshake{
		Header: handshake.Header{MessageSequence: seq},
		Message: &handshake.MessageClientHello{
			Version:            version,
			Random:             handshake.Random{},
			CipherSuiteIDs:     []uint16{},
			CompressionMethods: defaultCompressionMethods(),
			Extensions:         exts,
		},
	}

	raw, err := content.Marshal()
	require.NoError(t, err)

	cache.Push(raw, 0, seq, handshake.TypeClientHello, true)

	return raw
}

func flight13_2Context(state *dtlsstate.State, cache *dtlsflight.Cache, cfg *handshakeConfig) *handshakeContext13 {
	return &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: newHandshakeTranscript13(),
	}
}

func TestFlight13_2Parse(t *testing.T) {
	cookie := []byte{0xde, 0xad, 0xbe, 0xef}

	t.Run("AdvancesToFlight4OnMatchingCookie", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		exts := append(requiredClientHello13Extensions(t, cfg), &extension.CookieExt{Cookie: cookie})
		pushClientHello13(t, cache, protocol.Version1_2, exts)

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, dtlsflight13.Flight4, next)
		assert.Equal(t, 1, state.HandshakeRecvSequence)
	})

	t.Run("KeepsWaitingWhenNoClientHelloCached", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, dtlsflight13.Flight(0), next)
		assert.Equal(t, 0, state.HandshakeRecvSequence)
	})

	t.Run("KeepsWaitingWhenCookieNotYetEchoed", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie, ServerName: "original.example"}
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		exts := append(requiredClientHello13Extensions(t, cfg), &extension.ServerName{ServerName: "poison.example"})
		pushClientHello13(t, cache, protocol.Version1_2, exts)

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, dtlsflight13.Flight(0), next)
		assert.Equal(t, 0, state.HandshakeRecvSequence)
		assert.Equal(t, "original.example", state.ServerName)
		assert.Empty(t, state.RemoteSignatureSchemes)
		assert.Empty(t, state.RemoteGroups)
	})

	t.Run("RejectsCookieMismatch", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie, ServerName: "original.example"}
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		exts := append(requiredClientHello13Extensions(t, cfg), &extension.ServerName{ServerName: "poison.example"},
			&extension.CookieExt{Cookie: []byte{0x00, 0x01, 0x02, 0x03}})
		pushClientHello13(t, cache, protocol.Version1_2, exts)

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrCookieMismatch)
		assert.Equal(t, dtlsflight13.Flight(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.AccessDenied}, dtlsAlert)
		assert.Equal(t, 0, state.HandshakeRecvSequence)
		assert.Equal(t, "original.example", state.ServerName)
		assert.Empty(t, state.RemoteSignatureSchemes)
		assert.Empty(t, state.RemoteGroups)
	})

	t.Run("RejectsUnsupportedVersion", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		pushClientHello13(t, cache, protocol.Version{Major: 0xfe, Minor: 0xfd - 1}, []extension.Extension{
			&extension.CookieExt{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
		assert.Equal(t, dtlsflight13.Flight(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlsAlert)
	})

	t.Run("RejectsMissingCertificateAuthExtensions", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		pushClientHello13(t, cache, protocol.Version1_2, []extension.Extension{
			&extension.CookieExt{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrMissingClientHelloExtension)
		assert.Equal(t, dtlsflight13.Flight(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
	})
}
