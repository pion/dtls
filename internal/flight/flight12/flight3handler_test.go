// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"context"
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/internal/extensionnegotiation"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlight3GenerateReusesHookOnlyConnectionIDAfterVersionDowngrade(t *testing.T) {
	for name, cid := range map[string][]byte{
		"Empty":    {},
		"NonEmpty": {0xcc},
	} {
		t.Run(name, func(t *testing.T) {
			state13 := dtlsstate.NewState13(true)
			state13.SetLocalConnectionID(cid)
			state13.LocalCIDOffered = true
			state := dtlsstate.Activate12(&state13)
			cfg := &dtlsconfig.HandshakeConfig{
				ClientHelloMessageHook: func(clientHello handshake.MessageClientHello) handshake.Message {
					clientHello.Extensions = append(clientHello.Extensions, &extension.ConnectionID{CID: cid})

					return &clientHello
				},
			}

			packets, dtlsAlert, err := generateForTest(t, Flight3, nil, state, nil, cfg)
			require.NoError(t, err)
			require.Nil(t, dtlsAlert)
			require.Len(t, packets, 1)
			hand, ok := packets[0].Record.Content.(*handshake.Handshake)
			require.True(t, ok)
			clientHello, ok := hand.Message.(*handshake.MessageClientHello)
			require.True(t, ok)

			connectionIDs := make([][]byte, 0, 1)
			for _, ext := range clientHello.Extensions {
				if connectionID, ok := ext.(*extension.ConnectionID); ok {
					connectionIDs = append(connectionIDs, connectionID.CID)
				}
			}
			require.Len(t, connectionIDs, 1)
			assert.Equal(t, cid, connectionIDs[0])
		})
	}
}

func TestFlight3GenerateRestoresCurveExtensionsAfterVersionDowngrade(t *testing.T) {
	state13 := dtlsstate.NewState13(true)
	state := dtlsstate.Activate12(&state13)
	cfg := &dtlsconfig.HandshakeConfig{EllipticCurves: []elliptic.Curve{elliptic.X25519}}

	packets, dtlsAlert, err := generateForTest(t, Flight3, nil, state, nil, cfg)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, elliptic.X25519, state.NamedCurve)

	handshakeMessage, ok := packets[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	clientHello, ok := handshakeMessage.Message.(*handshake.MessageClientHello)
	require.True(t, ok)
	assert.Contains(t, clientHello.Extensions, &extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519}})
	assert.Contains(t, clientHello.Extensions, &extension12.SupportedPointFormats{
		PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
	})
}

func TestFlight3RejectsUnsolicitedServerHelloExtension(t *testing.T) {
	state := newTestState12()
	clientHello := &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		CipherSuiteIDs:     []uint16{uint16(ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)},
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
	}
	_, offer, err := extensionnegotiation.FinalizeClientHello(clientHello, nil)
	assert.NoError(t, err)
	state.LocalClientHelloSnapshots.Record(offer)

	cipherSuiteID := uint16(ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	raw, err := (&handshake.Handshake{Message: &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
		Extensions: []extension.Value{
			extension.Raw{Type: 0xfafa},
		},
	}}).Marshal()
	assert.NoError(t, err)
	cache := dtlsflight.NewCache()
	cache.Push(raw, 0, 0, handshake.TypeServerHello, false)

	_, dtlsAlert, err := parseForTest(
		t, Flight3, context.Background(), nil, state, cache, &dtlsconfig.HandshakeConfig{},
	)
	assert.ErrorIs(t, err, dtlserrors.ErrUnsolicitedExtension)
	assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.UnsupportedExtension}, dtlsAlert)
}
