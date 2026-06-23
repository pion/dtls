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
