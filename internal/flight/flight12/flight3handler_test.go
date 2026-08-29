// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"context"
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/logging"
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
			recordCH12(t, &state13.LocalClientHelloSnapshots, &extension.ConnectionID{CID: cid})
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
			hand, ok := packets[0].Content.(*handshake.Handshake)
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
	recordCH12(t, &state13.LocalClientHelloSnapshots)
	state := dtlsstate.Activate12(&state13)
	cfg := &dtlsconfig.HandshakeConfig{EllipticCurves: []elliptic.Curve{elliptic.X25519}}

	packets, dtlsAlert, err := generateForTest(t, Flight3, nil, state, nil, cfg)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, elliptic.X25519, state.NamedCurve)

	handshakeMessage, ok := packets[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	clientHello, ok := handshakeMessage.Message.(*handshake.MessageClientHello)
	require.True(t, ok)
	assert.Contains(t, clientHello.Extensions, &extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519}})
	assert.Contains(t, clientHello.Extensions, &extension12.SupportedPointFormats{PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed}})
}

func TestFlight3GenerateValidatesRetryWithEmptyCookie(t *testing.T) {
	state := newTestState12()
	suite := ciphersuite.ForID(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	cfg := &dtlsconfig.HandshakeConfig{LocalCipherSuites: []dtlsconfig.CipherSuite{suite}, EllipticCurves: []elliptic.Curve{elliptic.X25519}}
	_, _, err := generateForTest(t, Flight1, nil, state, nil, cfg)
	require.NoError(t, err)
	state.HasHelloVerifyRequest = true

	cfg.ClientHelloMessageHook = func(clientHello handshake.MessageClientHello) handshake.Message {
		clientHello.Random.RandomBytes[0] ^= 0xff

		return &clientHello
	}
	packets, dtlsAlert, err := generateForTest(t, Flight3, nil, state, nil, cfg)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidClientHello)
	require.Nil(t, dtlsAlert)
	require.Nil(t, packets)
}

func TestFlight3RejectsUnsolicitedServerHelloExtension(t *testing.T) {
	state := newTestState12()
	clientHello := &handshake.MessageClientHello{Version: protocol.Version1_2, CipherSuiteIDs: []uint16{uint16(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}, CompressionMethods: dtlsflight.DefaultCompressionMethods()}
	_, offer, err := negotiation.FinalizeClientHello(clientHello, nil)
	require.NoError(t, err)
	require.NoError(t, state.LocalClientHelloSnapshots.Record(offer))

	cipherSuiteID := uint16(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	raw, err := (&handshake.Handshake{Message: &handshake.MessageServerHello{Version: protocol.Version1_2, CipherSuiteID: &cipherSuiteID, CompressionMethod: dtlsflight.DefaultCompressionMethods()[0], Extensions: []extension.Value{extension.Raw{Type: 0xfafa}}}}).Marshal()
	require.NoError(t, err)
	cache := dtlsflight.NewCache()
	cache.Push(raw, 0, 0, handshake.TypeServerHello, false)

	_, dtlsAlert, err := parseForTest(
		t, Flight3, context.Background(), nil, state, cache, &dtlsconfig.HandshakeConfig{},
	)
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidServerHello)
	assert.ErrorIs(t, err, dtlserrors.ErrUnsolicitedExtension)
	assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.UnsupportedExtension}, dtlsAlert)
}

func TestFlight3DoesNotCommitConnectionIDBeforeSuccess(t *testing.T) {
	state := newTestState12()
	state.IsClient, state.SessionID = true, []byte{1}
	recordCH12(t, &state.LocalClientHelloSnapshots, &extension.ConnectionID{CID: []byte{0xc1}})
	suite := ciphersuite.ForID(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	cfg := &dtlsconfig.HandshakeConfig{LocalCipherSuites: []dtlsconfig.CipherSuite{suite}, HasSessionStore: true, DelSession: func([]byte) error { return dtlserrors.ErrInvalidPacket }, Log: logging.NewDefaultLoggerFactory().NewLogger("dtls")}
	cipherSuiteID := uint16(suite.ID())
	raw, err := (&handshake.Handshake{Message: &handshake.MessageServerHello{Version: protocol.Version1_2, SessionID: []byte{2}, CipherSuiteID: &cipherSuiteID, CompressionMethod: dtlsflight.DefaultCompressionMethods()[0], Extensions: []extension.Value{&extension.ConnectionID{CID: []byte{0x51}}}}}).Marshal()
	require.NoError(t, err)
	cache := dtlsflight.NewCache()
	cache.Push(raw, 0, 0, handshake.TypeServerHello, false)

	_, dtlsAlert, err := parseForTest(t, Flight3, t.Context(), nil, state, cache, cfg)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidPacket)
	assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, dtlsAlert)
	assert.False(t, state.LocalCIDOffered || state.RemoteCIDOffered)
	assert.Nil(t, state.LocalConnectionID())
	assert.Nil(t, state.RemoteConnectionID)
}

func TestFlight2RejectsChangedConnectionID(t *testing.T) {
	state := newTestState12()
	state.Cookie, state.HandshakeRecvSequence = []byte{0xc0}, 1
	recordCH12(t, &state.RemoteClientHelloSnapshots, &extension.ConnectionID{CID: []byte{1}})
	raw, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageClientHello{Version: protocol.Version1_2, Cookie: state.Cookie, CompressionMethods: dtlsflight.DefaultCompressionMethods(), Extensions: []extension.Value{&extension.ConnectionID{CID: []byte{2}}}},
	}).Marshal()
	require.NoError(t, err)
	cache := dtlsflight.NewCache()
	cache.Push(raw, 0, 1, handshake.TypeClientHello, true)

	_, dtlsAlert, err := parseForTest(t, Flight2, t.Context(), nil, state, cache, &dtlsconfig.HandshakeConfig{})
	require.ErrorIs(t, err, dtlserrors.ErrInvalidClientHello)
	assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlsAlert)
	cid, present := negotiation.ConnectionIDOffer(state.RemoteClientHelloSnapshots.Current())
	assert.Equal(t, []byte{1}, cid)
	assert.True(t, present)
}

func TestFlight2CommitsValidatedClientHello2AsCurrentOffer(t *testing.T) {
	state := newTestState12()
	state.Cookie, state.HandshakeRecvSequence = []byte{0xc0}, 1
	recordCH12(t, &state.RemoteClientHelloSnapshots,
		extension.Raw{Type: 0xfefe, Data: []byte{0x01}},
	)
	retry := &handshake.MessageClientHello{Version: protocol.Version1_2, Cookie: state.Cookie, CompressionMethods: dtlsflight.DefaultCompressionMethods(), Extensions: []extension.Value{extension.Raw{Type: 0xfefe, Data: []byte{0x02}}}}
	rawRetry, err := (&handshake.Handshake{
		Header: handshake.Header{MessageSequence: 1}, Message: retry,
	}).Marshal()
	require.NoError(t, err)
	cache := dtlsflight.NewCache()
	cache.Push(rawRetry, 0, 1, handshake.TypeClientHello, true)

	next, dtlsAlert, err := parseForTest(t, Flight2, t.Context(), nil, state, cache, &dtlsconfig.HandshakeConfig{EllipticCurves: []elliptic.Curve{elliptic.X25519}})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight4, next)
	current, present := state.RemoteClientHelloSnapshots.Current().Extension(0xfefe)
	require.True(t, present)
	assert.Equal(t, []byte{0x02}, current.Data)
}

func TestFlight4bGenerateCommitsConnectionIDOnce(t *testing.T) {
	for name, test := range map[string]struct{ clientCID, serverCID []byte }{"bidirectional": {[]byte{0xc1}, []byte{0x51}}, "empty client CID": {nil, []byte{0x51}}, "empty server CID": {[]byte{0xc1}, nil}, "both CIDs are empty": {}} {
		t.Run(name, func(t *testing.T) {
			state := newTestState12()
			state.CipherSuite = ciphersuite.ForID(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
			state.LocalVerifyData = []byte{1}
			recordCH12(t, &state.RemoteClientHelloSnapshots, &extension.ConnectionID{CID: test.clientCID})
			calls := 0
			cfg := &dtlsconfig.HandshakeConfig{ConnectionIDGenerator: func() []byte {
				calls++

				return test.serverCID
			}}
			for range 2 {
				packets, _, err := generateForTest(t, Flight4b, nil, state, dtlsflight.NewCache(), cfg)
				require.NoError(t, err)
				require.Len(t, packets, 3)
				assert.Equal(t, len(test.clientCID) > 0, state.ShouldWrapConnectionID())
			}
			assert.Equal(t, 1, calls)
			assert.True(t, state.LocalCIDOffered && state.RemoteCIDOffered)
			assert.Equal(t, string(test.serverCID), string(state.LocalConnectionID()))
			assert.Equal(t, string(test.clientCID), string(state.RemoteConnectionID))
		})
	}
}

func TestFlight4bGenerateDoesNotCommitConnectionIDAfterLateResponseError(t *testing.T) {
	state := newTestState12()
	state.CipherSuite = ciphersuite.ForID(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	state.LocalVerifyData = []byte{1}
	recordCH12(t, &state.RemoteClientHelloSnapshots, &extension.ConnectionID{CID: []byte{0xc1}})
	cfg := &dtlsconfig.HandshakeConfig{
		ConnectionIDGenerator: func() []byte { return []byte{0x51} },
		ServerHelloMessageHook: func(serverHello handshake.MessageServerHello) handshake.Message {
			serverHello.Extensions = append(serverHello.Extensions, extension.Raw{Type: 0xfafa})

			return &serverHello
		},
	}

	_, _, err := generateForTest(t, Flight4b, nil, state, nil, cfg)
	require.ErrorIs(t, err, dtlserrors.ErrUnsolicitedExtension)
	var dtlsAlert *alert.Alert
	require.ErrorAs(t, err, &dtlsAlert)
	assert.Equal(t, alert.UnsupportedExtension, dtlsAlert.Description)
	assert.False(t, state.LocalCIDOffered || state.RemoteCIDOffered)
	assert.Nil(t, state.LocalConnectionID())
	assert.Nil(t, state.RemoteConnectionID)
}

func TestFlight5bFinishedUsesCommittedServerConnectionID(t *testing.T) {
	for name, decision := range map[string]*negotiation.ConnectionID{"not negotiated": nil, "bidirectional": {ClientCID: []byte{0xc1}, ServerCID: []byte{0x51}}, "empty server CID": {ClientCID: []byte{0xc1}}} {
		t.Run(name, func(t *testing.T) {
			state := newTestState12()
			state.IsClient, state.LocalVerifyData = true, []byte{1}
			state.CommitNegotiatedExtensions(decision)
			packets, _, err := generateForTest(t, Flight5b, nil, state, nil, &dtlsconfig.HandshakeConfig{})
			require.NoError(t, err)
			require.Len(t, packets, 2)
			assert.Equal(t, decision != nil && len(decision.ServerCID) > 0, state.ShouldWrapConnectionID())
		})
	}
}

func recordCH12(t *testing.T, snapshots *negotiation.ClientHelloSnapshots, extensions ...extension.Value) {
	t.Helper()
	_, snapshot, err := negotiation.FinalizeClientHello(&handshake.MessageClientHello{Version: protocol.Version1_2, CompressionMethods: dtlsflight.DefaultCompressionMethods(), Extensions: extensions}, nil)
	require.NoError(t, err)
	require.NoError(t, snapshots.Record(snapshot))
}
