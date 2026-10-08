// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v5/dpipe"
	"github.com/stretchr/testify/assert"
)

func TestSelectEllipticCurve(t *testing.T) {
	for _, tt := range []struct {
		name       string
		configured []elliptic.Curve
		offered    []elliptic.Curve
		want       elliptic.Curve
		wantOK     bool
	}{
		{
			name:       "picks the first offered curve the server is configured for",
			configured: []elliptic.Curve{elliptic.P256, elliptic.P384},
			offered:    []elliptic.Curve{elliptic.X25519, elliptic.P256},
			want:       elliptic.P256,
			wantOK:     true,
		},
		{
			name:       "honors the client's preference order",
			configured: []elliptic.Curve{elliptic.P256, elliptic.P384},
			offered:    []elliptic.Curve{elliptic.P384, elliptic.P256},
			want:       elliptic.P384,
			wantOK:     true,
		},
		{
			name:       "reports no match when the offered curves are not configured",
			configured: []elliptic.Curve{elliptic.P256, elliptic.P384},
			offered:    []elliptic.Curve{elliptic.X25519},
			wantOK:     false,
		},
		{
			name:       "reports no match when the server has no configured curves",
			configured: nil,
			offered:    []elliptic.Curve{elliptic.P256},
			wantOK:     false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := selectEllipticCurve(tt.configured, tt.offered)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// handshakeWithCurves drives a full handshake where the server and client are
// each pinned to the given elliptic curves, and reports the server-side error.
// It exercises the accept path in flight0Parse, which selects the negotiated
// curve from the intersection of the client's offer and the server's config.
func handshakeWithCurves(t *testing.T, serverCurves, clientCurves []elliptic.Curve) error {
	t.Helper()

	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		conn *Conn
		err  error
	}
	srvCh := make(chan result, 1)
	go func() {
		conn, err := testServer(
			ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(),
			&Config{EllipticCurves: serverCurves}, true,
		)
		srvCh <- result{conn, err}
	}()

	clientConn, _ := testClient(
		ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(),
		&Config{EllipticCurves: clientCurves}, true,
	)
	srv := <-srvCh

	if clientConn != nil {
		_ = clientConn.Close()
	}
	if srv.conn != nil {
		_ = srv.conn.Close()
	}

	return srv.err
}

func TestFlight0AcceptCurveSelection(t *testing.T) {
	nist := []elliptic.Curve{elliptic.P256, elliptic.P384}

	t.Run("negotiates a mutually-supported curve", func(t *testing.T) {
		// A client offering X25519 first, then P-256, against a server configured
		// for NIST curves only: the server selects P-256 rather than failing.
		err := handshakeWithCurves(t, nist, []elliptic.Curve{elliptic.X25519, elliptic.P256})
		assert.NoError(t, err)
	})

	t.Run("refuses when no offered curve is configured", func(t *testing.T) {
		// A client offering only X25519 against a NIST-only server: no shared
		// curve, so the server refuses rather than negotiating an unconfigured one.
		err := handshakeWithCurves(t, nist, []elliptic.Curve{elliptic.X25519})
		assert.Error(t, err)
	})
}
