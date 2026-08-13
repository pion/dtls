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
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/transport/v4/dpipe"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// This test configures only a DTLS 1.2 cipher suite. X25519MLKEM768 is a
	// DTLS 1.3-only group.
	// todo: handle cases like this when configured by end user.
	// nolint:godox
	expectedCurves := make([]elliptic.Curve, 0, len(defaultCurves))
	for _, curve := range defaultCurves {
		if curve != elliptic.X25519MLKEM768 {
			expectedCurves = append(expectedCurves, curve)
		}
	}
	var actualCurves []elliptic.Curve

	rand.Shuffle(len(expectedCurves), func(i, j int) {
		expectedCurves[i], expectedCurves[j] = expectedCurves[j], expectedCurves[i]
	})

	type result struct {
		conn *Conn
		err  error
	}
	clientResult := make(chan result, 1)
	ca, cb := dpipe.Pipe()
	caAnalyzer := &connWithCallback{Conn: ca}
	caAnalyzer.onWrite = func(in []byte) {
		messages, err := recordlayer.UnpackDatagram(in)
		assert.NoError(t, err)

		for i := range messages {
			h := &handshake.Handshake{}
			_ = h.Unmarshal(messages[i][recordlayer.FixedHeaderSize:])

			if h.Header.Type == handshake.TypeClientHello {
				clientHello := &handshake.MessageClientHello{}
				msg, err := h.Message.Marshal()

				assert.NoError(t, err)
				assert.NoError(t, clientHello.Unmarshal(msg))

				for _, e := range clientHello.Extensions {
					if e.ExtensionType() == extension.TypeSupportedGroups {
						if c, ok := e.(*extension.SupportedGroups); ok {
							actualCurves = c.Groups
						}
					}
				}
			}
		}
	}

	go func() {
		client, err := testClient(
			ctx,
			dtlsnet.PacketConnFromConn(caAnalyzer),
			caAnalyzer.RemoteAddr(),
			[]ClientOption{
				WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				WithEllipticCurves(expectedCurves...),
			},
			false,
		)
		clientResult <- result{conn: client, err: err}
	}()

	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), []ServerOption{
		WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
	}, true)
	client := <-clientResult
	require.NoError(t, err)
	require.NoError(t, client.err)
	assert.NoError(t, server.Close())
	assert.NoError(t, client.conn.Close())

	for i := range expectedCurves {
		assert.Equal(t, expectedCurves[i], actualCurves[i], "curves in SupportedEllipticCurves mismatch")
	}
}
