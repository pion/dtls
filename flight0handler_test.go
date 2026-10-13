// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v5/dpipe"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
)

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
		err := handshakeWithCurves(t, nist, []elliptic.Curve{elliptic.X25519, elliptic.P256})
		assert.NoError(t, err)
	})

	t.Run("refuses when no offered curve is configured", func(t *testing.T) {
		err := handshakeWithCurves(t, nist, []elliptic.Curve{elliptic.X25519})
		assert.Error(t, err)
	})
}

func TestSelectAcceptCurve(t *testing.T) {
	cfg := &handshakeConfig{ellipticCurves: []elliptic.Curve{elliptic.P256, elliptic.P384}}
	for _, tt := range []struct {
		name           string
		offered        []elliptic.Curve
		offeredPresent bool
		wantRefuse     bool
		wantCurve      elliptic.Curve
	}{
		{
			name:           "empty supported groups",
			offered:        nil,
			offeredPresent: true,
			wantRefuse:     true,
		},
		{
			name:           "absent supported groups",
			offered:        nil,
			offeredPresent: false,
			wantRefuse:     false,
			wantCurve:      elliptic.P256,
		},
		{
			name:           "client preference",
			offered:        []elliptic.Curve{elliptic.X25519, elliptic.P384, elliptic.P256},
			offeredPresent: true,
			wantRefuse:     false,
			wantCurve:      elliptic.P384,
		},
		{
			name:           "disjoint curves",
			offered:        []elliptic.Curve{elliptic.X25519},
			offeredPresent: true,
			wantRefuse:     true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := &State{namedCurve: elliptic.P256}
			alertPtr, err := selectAcceptCurve(state, cfg, tt.offered, tt.offeredPresent)
			if tt.wantRefuse {
				assert.Error(t, err)
				assert.NotNil(t, alertPtr)

				return
			}
			assert.NoError(t, err)
			assert.Nil(t, alertPtr)
			assert.Equal(t, tt.wantCurve, state.namedCurve)
			assert.NotNil(t, state.localKeypair, "keypair must be generated for the negotiated curve")
		})
	}
}

func TestFlight0ResumeIgnoresCurveConfig(t *testing.T) {
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ss := &memSessStore{}
	id, _ := hex.DecodeString("9b9fc92255634d9fb109febed42166717bb8ded8c738ba71bc7f2a0d9dae0306")
	secret, _ := hex.DecodeString(
		"2e942a37aca5241deb2295b5fcedac221c7078d2503d2b62aeb48c880d7da73c001238b708559686b9da6e829c05ead7",
	)
	sess := Session{ID: id, Secret: secret}

	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()
	_ = ss.Set(id, sess)
	_ = ss.Set([]byte(ca.RemoteAddr().String()+"_example.com"), sess)

	type result struct {
		c   *Conn
		err error
	}
	clientRes := make(chan result, 1)
	go func() {
		config := &Config{
			CipherSuites:   []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerName:     "example.com",
			SessionStore:   ss,
			EllipticCurves: []elliptic.Curve{elliptic.X25519},
			MTU:            100,
		}
		c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), config, false)
		clientRes <- result{c, err}
	}()

	config := &Config{
		CipherSuites:   []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ServerName:     "example.com",
		SessionStore:   ss,
		EllipticCurves: []elliptic.Curve{elliptic.P256},
		MTU:            100,
	}
	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true)
	assert.NoError(t, err)

	if err == nil {
		state, ok := server.ConnectionState()
		assert.True(t, ok)
		assert.Equal(t, id, state.SessionID, "handshake must have resumed, not fallen back to a fresh handshake")
	}

	res := <-clientRes
	assert.NoError(t, res.err)

	if res.c != nil {
		_ = res.c.Close()
	}
	if server != nil {
		_ = server.Close()
	}
}

func TestFlight0PSKFallbackIgnoresCurveConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		suites []CipherSuiteID
		curve  elliptic.Curve
		want   CipherSuiteID
	}{
		{"plain PSK only", []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8}, elliptic.P256, TLS_PSK_WITH_AES_128_CCM_8},
		{
			"disjoint curves",
			[]CipherSuiteID{TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, TLS_PSK_WITH_AES_128_CCM_8},
			elliptic.P256, TLS_PSK_WITH_AES_128_CCM_8,
		},
		{
			"shared curve",
			[]CipherSuiteID{TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, TLS_PSK_WITH_AES_128_CCM_8},
			elliptic.X25519, TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testFlight0PSKFallback(t, tc.suites, tc.curve, tc.want)
		})
	}
}

func testFlight0PSKFallback(t *testing.T, suites []CipherSuiteID, curve elliptic.Curve, want CipherSuiteID) {
	t.Helper()
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	psk := func([]byte) ([]byte, error) { return []byte{0xAB, 0xC1, 0x23}, nil }

	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	type result struct {
		c   *Conn
		err error
	}
	clientRes := make(chan result, 1)
	go func() {
		config := &Config{
			PSK:             psk,
			PSKIdentityHint: []byte("hint"),
			CipherSuites:    []CipherSuiteID{TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, TLS_PSK_WITH_AES_128_CCM_8},
			EllipticCurves:  []elliptic.Curve{elliptic.X25519},
		}
		c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), config, false)
		clientRes <- result{c, err}
	}()

	config := &Config{
		PSK:             psk,
		PSKIdentityHint: []byte("hint"),
		CipherSuites:    suites,
		EllipticCurves:  []elliptic.Curve{curve},
	}
	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, false)
	assert.NoError(t, err)

	if err == nil {
		state, ok := server.ConnectionState()
		assert.True(t, ok)
		assert.Equal(t, want, state.CipherSuiteID)
	}

	res := <-clientRes
	assert.NoError(t, res.err)

	if res.c != nil {
		_ = res.c.Close()
	}
	if server != nil {
		_ = server.Close()
	}
}
