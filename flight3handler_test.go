// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/transport/v4/dpipe"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
)

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
