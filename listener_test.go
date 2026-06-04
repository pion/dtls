// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package dtls

import (
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenerPacketConn(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	pConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)

	listener, err := ListenPacketConnWithOptions(pConn, WithCertificates(cert))
	require.NoError(t, err)
	assert.Equal(t, pConn.LocalAddr(), listener.Addr())

	serverDone := make(chan error, 1)
	go func() {
		conn, aErr := listener.Accept()
		if aErr != nil {
			serverDone <- aErr

			return
		}
		buf := make([]byte, 16)
		n, rErr := conn.Read(buf)
		if rErr != nil {
			serverDone <- rErr

			return
		}
		if _, wErr := conn.Write(buf[:n]); wErr != nil {
			serverDone <- wErr

			return
		}
		serverDone <- conn.Close()
	}()

	raddr, ok := listener.Addr().(*net.UDPAddr)
	require.True(t, ok)
	client, err := DialWithOptions("udp", raddr, WithCertificates(cert), WithInsecureSkipVerify(true))
	require.NoError(t, err)

	_, err = client.Write([]byte("hello"))
	require.NoError(t, err)
	buf := make([]byte, 16)
	n, err := client.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))

	assert.NoError(t, client.Close())
	assert.NoError(t, <-serverDone)

	// Closing the listener must close the supplied connection.
	assert.NoError(t, listener.Close())
	_, _, err = pConn.ReadFromUDP(buf)
	assert.ErrorIs(t, err, net.ErrClosed)
}
