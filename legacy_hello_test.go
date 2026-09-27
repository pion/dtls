// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
)

// startPSKServer brings up a PSK listener; the accepted connection is
// handshaken in the background and delivered on the returned channel (closed
// when the server side is done, with or without error).
func startPSKServer(t *testing.T, opts ...ServerOption) (net.Listener, chan *Conn) {
	t.Helper()

	ln, err := ListenWithOptions("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		append([]ServerOption{
			WithPSK(func([]byte) ([]byte, error) { return []byte("secret"), nil }),
			WithPSKIdentityHint([]byte("pion")),
			WithCipherSuites(TLS_PSK_WITH_AES_128_GCM_SHA256),
		}, opts...)...)
	assert.NoError(t, err)

	connCh := make(chan *Conn, 1)
	go func() {
		defer close(connCh)
		sconn, err := ln.Accept()
		if err != nil {
			return
		}
		conn := sconn.(*Conn)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := conn.HandshakeContext(ctx); err != nil {
			cancel()
			_ = conn.Close()
			return
		}
		cancel()
		// Ownership of the accepted conn is transferred to the receiver.
		connCh <- conn
	}()

	return ln, connCh
}

// legacyClientHelloHook builds the ClientHello the way an OpenSSL-built
// openconnect client does: client_version is DTLS 1.0 (0xFEFF) even though
// the client is ready to negotiate 1.2 (fake SSL_SESSION construction,
// openssl-dtls.c). Using the hook (rather than rewriting bytes on the wire)
// keeps the client's own handshake transcript consistent with what it sends.
func legacyClientHelloHook(ch handshake.MessageClientHello) handshake.Message {
	ch.Version = protocol.Version1_0

	return &ch
}

// dialLegacyClient connects a PSK client whose ClientHellos carry the
// DTLS 1.0 legacy client_version.
func dialLegacyClient(t *testing.T, addr net.Addr) *Conn {
	t.Helper()

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = pc.Close()
	})

	conn, err := ClientWithOptions(pc, addr,
		WithPSK(func([]byte) ([]byte, error) { return []byte("secret"), nil }),
		WithPSKIdentityHint([]byte("pion")),
		WithCipherSuites(TLS_PSK_WITH_AES_128_GCM_SHA256),
		WithClientHelloMessageHook(legacyClientHelloHook),
	)
	assert.NoError(t, err)

	return conn
}

func TestLegacyClientHelloAccepted(t *testing.T) {
	ln, serverCh := startPSKServer(t, WithLegacyClientHello())
	defer func() {
		assert.NoError(t, ln.Close())
	}()

	client := dialLegacyClient(t, ln.Addr())
	defer func() {
		_ = client.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatalf("handshake with legacy-version ClientHello: %v", err)
	}
	// The server side must have completed its handshake too.
	select {
	case serverConn := <-serverCh:
		defer func() {
			_ = serverConn.Close()
		}()
	case <-time.After(10 * time.Second):
		t.Fatal("server handshake did not complete")
	}
}

func TestLegacyClientHelloRejectedByDefault(t *testing.T) {
	ln, serverCh := startPSKServer(t)
	defer func() {
		assert.NoError(t, ln.Close())
	}()

	client := dialLegacyClient(t, ln.Addr())
	defer func() {
		_ = client.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.HandshakeContext(ctx); err == nil {
		t.Fatal("expected the strict server to reject the legacy-version ClientHello")
	}
	// The server side must have failed its handshake as well (channel closed
	// without delivering a connection).
	select {
	case conn, ok := <-serverCh:
		if ok {
			_ = conn.Close()
			t.Fatal("server completed a handshake from a legacy ClientHello without the option")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not process the rejected ClientHello")
	}
}
