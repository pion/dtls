// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/transport/v5/dpipe"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerKeyExchangeCurveOffer(t *testing.T) {
	for _, suiteID := range []CipherSuiteID{
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
		TLS_PSK_WITH_AES_128_GCM_SHA256,
	} {
		t.Run(suiteID.String(), func(t *testing.T) {
			for _, offered := range []bool{false, true} {
				name := "unoffered"
				if offered {
					name = "offered"
				}
				t.Run(name, func(t *testing.T) {
					peerKey, err := elliptic.GenerateKeypair(elliptic.P384)
					require.NoError(t, err)
					state := &State{cipherSuite: cipherSuiteForID(suiteID, nil)}
					cfg := &handshakeConfig{ellipticCurves: []elliptic.Curve{elliptic.P256}}
					if offered {
						cfg.ellipticCurves = append(cfg.ellipticCurves, elliptic.P384)
					}
					pskCalls := 0
					if suiteID != TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 {
						cfg.localPSKCallback = func([]byte) ([]byte, error) {
							pskCalls++

							return []byte("test PSK"), nil
						}
					}
					message := &handshake.MessageServerKeyExchange{
						NamedCurve: elliptic.P384,
						PublicKey:  peerKey.PublicKey,
					}
					if suiteID == TLS_PSK_WITH_AES_128_GCM_SHA256 {
						message = &handshake.MessageServerKeyExchange{}
					}
					cache := newHandshakeCache()
					cacheFlight4TestMessage(t, cache, 0, 0, &handshake.MessageClientHello{
						Version: protocol.Version1_2, CompressionMethods: defaultCompressionMethods(),
						Extensions: []extension.Extension{
							&extension.SupportedEllipticCurves{EllipticCurves: cfg.ellipticCurves},
						},
					})
					alertPtr, err := handleServerKeyExchange(cache, state, cfg, message)
					if !offered && suiteID != TLS_PSK_WITH_AES_128_GCM_SHA256 {
						require.ErrorIs(t, err, errServerSelectedUnofferedCurve)
						require.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, alertPtr)
						require.Nil(t, state.localKeypair)
						require.Empty(t, state.preMasterSecret)
						require.Zero(t, pskCalls)

						return
					}
					require.NoError(t, err)
					require.Nil(t, alertPtr)
					require.NotEmpty(t, state.preMasterSecret)
					if suiteID != TLS_PSK_WITH_AES_128_GCM_SHA256 {
						require.Equal(t, elliptic.P384, state.localKeypair.Curve)
					}
				})
			}
		})
	}
}

// Assert that SupportedEllipticCurves is only sent when a ECC CipherSuite is available.
func TestSupportedEllipticCurves(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	expectedCurves := defaultCurves
	var actualCurves []elliptic.Curve

	rand.Shuffle(len(expectedCurves), func(i, j int) {
		expectedCurves[i], expectedCurves[j] = expectedCurves[j], expectedCurves[i]
	})

	clientErr := make(chan error, 1)
	ca, cb := dpipe.Pipe()
	caAnalyzer := &connWithCallback{Conn: ca}
	caAnalyzer.onWrite = func(in []byte) {
		messages, err := recordlayer.UnpackDatagram(in)
		assert.NoError(t, err)

		for i := range messages {
			h := &handshake.Handshake{}
			_ = h.Unmarshal(messages[i][recordlayer.FixedHeaderSize:])

			if h.Header.Type == handshake.TypeClientHello { //nolint:nestif
				clientHello := &handshake.MessageClientHello{}
				msg, err := h.Message.Marshal()

				assert.NoError(t, err)
				assert.NoError(t, clientHello.Unmarshal(msg))

				for _, e := range clientHello.Extensions {
					if e.TypeValue() == extension.SupportedEllipticCurvesTypeValue {
						if c, ok := e.(*extension.SupportedEllipticCurves); ok {
							actualCurves = c.EllipticCurves
						}
					}
				}
			}
		}
	}

	go func() {
		conf := &Config{
			CipherSuites:   []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			EllipticCurves: expectedCurves,
		}

		if client, err := testClient(
			ctx,
			dtlsnet.PacketConnFromConn(caAnalyzer),
			caAnalyzer.RemoteAddr(),
			conf,
			false,
		); err != nil {
			clientErr <- err
		} else {
			clientErr <- client.Close() // nolint:errcheck,contextcheck
		}
	}()

	config := &Config{
		CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}

	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true)
	assert.NoError(t, err)
	assert.NoError(t, server.Close())
	assert.NoError(t, <-clientErr)

	for i := range expectedCurves {
		assert.Equal(t, expectedCurves[i], actualCurves[i], "curves in SupportedEllipticCurves mismatch")
	}
}
