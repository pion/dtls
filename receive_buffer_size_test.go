// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

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

// Datagrams larger than the default receive buffer size were silently
// truncated by both the listener demux loop and the connection read loop,
// surfacing as read timeouts or EOF instead of data.
// https://github.com/pion/dtls/issues/642
func TestReceiveBufferSizeLargeDatagram(t *testing.T) {
	lim := test.TimeOut(30 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	// Larger than the 8192-byte default receive buffer, small enough that the
	// resulting datagram fits well under platform datagram limits (macOS caps
	// UDP datagrams at net.inet.udp.maxdgram, 9216 bytes by default).
	const payloadSize = 8500
	const bufferSize = 16384

	serverCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	listener, err := ListenWithOptions("udp",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		WithCertificates(serverCert),
		WithReceiveBufferSize(bufferSize),
	)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, listener.Close())
	}()

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	type readResult struct {
		data []byte
		err  error
	}
	serverRead := make(chan readResult, 1)

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverRead <- readResult{err: acceptErr}

			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, bufferSize)
		n, readErr := conn.Read(buf)
		serverRead <- readResult{data: buf[:n], err: readErr}

		assert.NoError(t, conn.Close())
	}()

	serverAddr, ok := listener.Addr().(*net.UDPAddr)
	require.True(t, ok)

	client, err := DialWithOptions("udp", serverAddr,
		WithInsecureSkipVerify(true),
		WithReceiveBufferSize(bufferSize),
	)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, client.Close())
	}()

	n, err := client.Write(payload)
	require.NoError(t, err)
	require.Equal(t, payloadSize, n)

	res := <-serverRead
	require.NoError(t, res.err)
	assert.Equal(t, payload, res.data)
}

func TestWithReceiveBufferSizeValidation(t *testing.T) {
	for _, size := range []int{0, -1} {
		_, err := buildConfig(WithReceiveBufferSize(size))
		assert.Error(t, err)
	}

	config, err := buildConfig(WithReceiveBufferSize(16384))
	assert.NoError(t, err)
	assert.Equal(t, 16384, config.ReceiveBufferSize)
}
