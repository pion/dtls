// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v5/dpipe"
	"github.com/pion/transport/v5/test"
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
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	psk := func([]byte) ([]byte, error) { return []byte{0xAB, 0xC1, 0x23}, nil }
	cipherSuites := []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256}

	ca, cb := dpipe.Pipe()
	defer func() { assert.NoError(t, ca.Close()) }()
	defer func() { assert.NoError(t, cb.Close()) }()

	cpc := &countingConn{PacketConn: dtlsnet.PacketConnFromConn(ca)}

	server, err := ServerWithOptions(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(),
		WithPSK(psk),
		WithPSKIdentityHint([]byte("pion")),
		WithCipherSuites(cipherSuites...),
	)
	assert.NoError(t, err)
	defer func() { _ = server.Close() }()

	client, err := ClientWithOptions(cpc, ca.RemoteAddr(),
		WithPSK(psk),
		WithPSKIdentityHint([]byte("pion")),
		WithCipherSuites(cipherSuites...),
	)
	assert.NoError(t, err)
	defer func() { _ = client.Close() }()

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.HandshakeContext(ctx) }()
	assert.NoError(t, client.HandshakeContext(ctx))
	select {
	case err := <-serverDone:
		assert.NoError(t, err)
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
