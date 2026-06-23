// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"testing"

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
	cfg.ellipticCurves = []elliptic.Curve{elliptic.P384, elliptic.P256}

	clientKeypair, err := elliptic.GenerateKeypair(elliptic.P384)
	require.NoError(t, err)
	staleServerKeypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	require.NoError(t, err)

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.localCipherSuites[0].ID()),
		},
		CompressionMethods: defaultCompressionMethods(),
		Extensions: []extension.Extension{
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

	state := &State{
		localVersion: protocol.Version1_3,
		namedCurve:   elliptic.X25519,
		localKeypair: staleServerKeypair,
	}
	cache := newHandshakeCache()
	cache.push(rawClientHello, cfg.initialEpoch, 0, handshake.TypeClientHello, true)

	nextFlight, dtlsAlert, err := flight13_0Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, flight13_2, nextFlight)
	require.NotNil(t, state.localKeypair)
	assert.Equal(t, elliptic.P384, state.namedCurve)
	assert.Equal(t, elliptic.P384, state.localKeypair.Curve)
}

func TestFlight13_0ParseRejectsClientHelloWithSelectedSupportedVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.localCipherSuites[0].ID()),
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

	state := &State{localVersion: protocol.Version1_3}
	cache := newHandshakeCache()
	cache.push(rawClientHello, cfg.initialEpoch, 0, handshake.TypeClientHello, true)

	nextFlight, dtlsAlert, err := flight13_0Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, errInvalidClientHello)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.IllegalParameter, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.Empty(t, state.remoteVersions)
}

func serverHelloFromFlight13_2(t *testing.T, state *State, cfg *handshakeConfig) *handshake.MessageServerHello {
	t.Helper()

	pkts, dtlsAlert, err := flight13_2Generate(nil, flight13_2Context(state, newHandshakeCache(), cfg))
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	require.NotNil(t, pkts[0].record)
	assert.Equal(t, protocol.Version1_2, pkts[0].record.Header.Version)

	content, ok := pkts[0].record.Content.(*handshake.Handshake)
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
		state := &State{localVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		assert.Equal(t, protocol.Version1_2, serverHello.Version)
		assert.Equal(t, [32]byte(handshake.HelloRetryRequestRandom()), serverHello.Random.MarshalFixed())
	})

	t.Run("ResetsHandshakeSendSequence", func(t *testing.T) {
		state := &State{localVersion: protocol.Version1_3, handshakeSendSequence: 7}
		cfg := testHandshakeConfig13(t)

		_, dtlsAlert, err := flight13_2Generate(nil, flight13_2Context(state, newHandshakeCache(), cfg))
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)

		assert.Equal(t, 0, state.handshakeSendSequence)
	})

	t.Run("AlwaysIncludesSupportedVersions", func(t *testing.T) {
		state := &State{localVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		require.True(t, ok, "SupportedVersions extension must always be present")
		assert.Equal(t, supportedVersionsRange(cfg.minVersion, cfg.maxVersion), supportedVersions.Versions)
	})

	t.Run("OmitsKeyShareAndCookieByDefault", func(t *testing.T) {
		state := &State{localVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		_, hasKeyShare := findKeyShare(serverHello.Extensions)
		assert.False(t, hasKeyShare, "KeyShare must be omitted when no remote key entries were offered")

		_, hasCookie := findCookie(serverHello.Extensions)
		assert.False(t, hasCookie, "Cookie must be omitted when no cookie is set")

		require.Len(t, serverHello.Extensions, 1)
	})

	t.Run("IncludesKeyShareWhenRemoteKeyEntriesPresent", func(t *testing.T) {
		state := &State{
			localVersion: protocol.Version1_3,
			namedCurve:   elliptic.X25519,
		}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		keyShare, ok := findKeyShare(serverHello.Extensions)
		require.True(t, ok, "KeyShare must be present when remote key entries were offered")
		require.NotNil(t, keyShare.SelectedGroup)
		assert.Equal(t, elliptic.X25519, *keyShare.SelectedGroup)
	})

	t.Run("IncludesCookieWhenSet", func(t *testing.T) {
		cookie := []byte{0x01, 0x02, 0x03, 0x04}
		state := &State{localVersion: protocol.Version1_3, cookie: cookie}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		cookieExt, ok := findCookie(serverHello.Extensions)
		require.True(t, ok, "Cookie must be present when set on state")
		assert.Equal(t, cookie, cookieExt.Cookie)
	})

	t.Run("IncludesAllExtensionsTogether", func(t *testing.T) {
		cookie := []byte{0xaa, 0xbb}
		state := &State{
			localVersion: protocol.Version1_3,
			namedCurve:   elliptic.P256,
			cookie:       cookie,
		}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		require.Len(t, serverHello.Extensions, 3)

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		require.True(t, ok)
		assert.Equal(t, supportedVersionsRange(cfg.minVersion, cfg.maxVersion), supportedVersions.Versions)

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
	cache *handshakeCache,
	version protocol.Version,
	exts []extension.Extension,
) {
	t.Helper()

	content := &handshake.Handshake{
		Header: handshake.Header{MessageSequence: 0},
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

	cache.push(raw, 0, 0, handshake.TypeClientHello, true)
}

func flight13_2Context(state *State, cache *handshakeCache, cfg *handshakeConfig) *handshakeContext13 {
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
		state := &State{localVersion: protocol.Version1_3, cookie: cookie}
		cache := newHandshakeCache()
		cfg := testHandshakeConfig13(t)

		pushClientHello13(t, cache, protocol.Version1_2, []extension.Extension{
			&extension.CookieExt{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13_2Parse(context.Background(), nil, flight13_2Context(state, cache, cfg))
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, flight13_4, next)
		assert.Equal(t, 1, state.handshakeRecvSequence)
	})

	t.Run("KeepsWaitingWhenNoClientHelloCached", func(t *testing.T) {
		state := &State{localVersion: protocol.Version1_3, cookie: cookie}
		cache := newHandshakeCache()
		cfg := testHandshakeConfig13(t)

		next, dtlsAlert, err := flight13_2Parse(context.Background(), nil, flight13_2Context(state, cache, cfg))
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, flightVal13(0), next)
		assert.Equal(t, 0, state.handshakeRecvSequence)
	})

	t.Run("KeepsWaitingWhenCookieNotYetEchoed", func(t *testing.T) {
		state := &State{localVersion: protocol.Version1_3, cookie: cookie}
		cache := newHandshakeCache()
		cfg := testHandshakeConfig13(t)

		pushClientHello13(t, cache, protocol.Version1_2, nil)

		next, dtlsAlert, err := flight13_2Parse(context.Background(), nil, flight13_2Context(state, cache, cfg))
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, flightVal13(0), next)
	})

	t.Run("RejectsCookieMismatch", func(t *testing.T) {
		state := &State{localVersion: protocol.Version1_3, cookie: cookie}
		cache := newHandshakeCache()
		cfg := testHandshakeConfig13(t)

		pushClientHello13(t, cache, protocol.Version1_2, []extension.Extension{
			&extension.CookieExt{Cookie: []byte{0x00, 0x01, 0x02, 0x03}},
		})

		next, dtlsAlert, err := flight13_2Parse(context.Background(), nil, flight13_2Context(state, cache, cfg))
		require.ErrorIs(t, err, errCookieMismatch)
		assert.Equal(t, flightVal13(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.AccessDenied}, dtlsAlert)
	})

	t.Run("RejectsUnsupportedVersion", func(t *testing.T) {
		state := &State{localVersion: protocol.Version1_3, cookie: cookie}
		cache := newHandshakeCache()
		cfg := testHandshakeConfig13(t)

		pushClientHello13(t, cache, protocol.Version{Major: 0xfe, Minor: 0xfd - 1}, []extension.Extension{
			&extension.CookieExt{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13_2Parse(context.Background(), nil, flight13_2Context(state, cache, cfg))
		require.ErrorIs(t, err, errUnsupportedProtocolVersion)
		assert.Equal(t, flightVal13(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlsAlert)
	})
}
