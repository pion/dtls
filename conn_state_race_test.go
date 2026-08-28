// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

// JS/WASM runs tests single-threaded and the handshake loop in this test
// exceeds the CI time limit there. The race it covers is meaningless without
// parallel goroutines anyway.

package dtls

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v4/dpipe"
	"github.com/stretchr/testify/require"
)

// slowConn adds latency to reads and writes to widen the race window
// between the handshake FSM goroutine and the polling goroutine.
type slowConn struct {
	net.Conn
	delay time.Duration
}

func (c *slowConn) Read(p []byte) (int, error) {
	time.Sleep(c.delay)

	return c.Conn.Read(p)
}

func (c *slowConn) Write(p []byte) (int, error) {
	time.Sleep(c.delay)

	return c.Conn.Write(p)
}

// TestRaceConnectionStateDuringHandshake polls ConnectionState from the main
// goroutine while the handshake FSM goroutine mutates the shared state
// fields (CipherSuite, SessionID, MasterSecret, RemoteRandom). Run with
// -race to verify the access is synchronized.
func TestRaceConnectionStateDuringHandshake(t *testing.T) { //nolint:cyclop
	serverCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	for range 20 {
		caRaw, cbRaw := dpipe.Pipe()
		caSlow := &slowConn{Conn: caRaw, delay: 100 * time.Microsecond}
		cbSlow := &slowConn{Conn: cbRaw, delay: 100 * time.Microsecond}

		ca, err := ClientWithOptions(
			dtlsnet.PacketConnFromConn(caSlow), caSlow.RemoteAddr(),
			WithInsecureSkipVerify(true),
		)
		require.NoError(t, err)
		cb, err := ServerWithOptions(
			dtlsnet.PacketConnFromConn(cbSlow), cbSlow.RemoteAddr(),
			WithCertificates(serverCert),
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		clientDone := make(chan error, 1)
		serverDone := make(chan error, 1)
		go func() { clientDone <- ca.HandshakeContext(ctx) }()
		go func() { serverDone <- cb.HandshakeContext(ctx) }()

		clientFinished, serverFinished := false, false
		for {
			_, _ = ca.ConnectionState()
			_, _ = cb.ConnectionState()

			select {
			case <-clientDone:
				clientFinished = true
			default:
			}
			select {
			case <-serverDone:
				serverFinished = true
			default:
			}
			if clientFinished && serverFinished {
				break
			}
		}

		require.NoError(t, ca.Close())
		require.NoError(t, cb.Close())
	}
}
