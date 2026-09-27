// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// countingConn counts outgoing datagrams (WriteTo calls).
type countingConn struct {
	net.PacketConn
	writes atomic.Int64
}

func (c *countingConn) WriteTo(b []byte, a net.Addr) (int, error) {
	c.writes.Add(1)

	return c.PacketConn.WriteTo(b, a)
}

func TestWriteBatch(t *testing.T) {
	ln, serverCh := startPSKServer(t)
	defer func() {
		assert.NoError(t, ln.Close())
	}()

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	assert.NoError(t, err)
	defer func() {
		_ = pc.Close()
	}()
	cpc := &countingConn{PacketConn: pc}

	client, err := ClientWithOptions(cpc, ln.Addr(),
		WithPSK(func([]byte) ([]byte, error) { return []byte("secret"), nil }),
		WithPSKIdentityHint([]byte("pion")),
		WithCipherSuites(TLS_PSK_WITH_AES_128_GCM_SHA256),
	)
	assert.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	assert.NoError(t, client.HandshakeContext(ctx))

	var server *Conn
	select {
	case server = <-serverCh:
		defer func() {
			_ = server.Close()
		}()
	case <-time.After(10 * time.Second):
		t.Fatal("server handshake did not complete")
	}

	payloads := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	before := cpc.writes.Load()
	assert.NoError(t, client.WriteBatch(payloads))

	// The server must read the payloads back as separate records, in order.
	for _, want := range payloads {
		assert.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
		buf := make([]byte, 128)
		n, err := server.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, string(want), string(buf[:n]))
	}

	// Three short records fit one datagram: exactly one write instead of
	// one per record.
	assert.Equal(t, int64(1), cpc.writes.Load()-before)
}
