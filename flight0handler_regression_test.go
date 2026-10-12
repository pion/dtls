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

// These two tests pin the regressions JoTurk reported on pion/dtls#1153: the
// accept-side curve selection must not run on paths that do not use a curve.
// Both reproduce by driving a full loopback handshake with a server whose
// configured EllipticCurves do NOT intersect the client's offered curves, on a
// path (resumption / plain-PSK) where that mismatch must be irrelevant.

// TestSelectAcceptCurve pins the accept-path curve decision, including the case a
// client advertises supported_groups listing only curves the server does not
// implement: pion's extension parser drops unknown curve IDs, so that arrives as
// an offered set that is present-but-empty. The server shares no curve with such
// a client and must refuse, rather than silently fall back to a curve the client
// never offered. A client that advertises no supported_groups at all keeps the
// server's default curve (RFC 8422 §5.1).
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
			name:           "refuses a present supported_groups with no server-usable curve",
			offered:        nil,
			offeredPresent: true,
			wantRefuse:     true,
		},
		{
			name:           "keeps the server default when no supported_groups was offered",
			offered:        nil,
			offeredPresent: false,
			wantRefuse:     false,
			wantCurve:      elliptic.P256, // the default set by flight0Generate
		},
		{
			name:           "negotiates the intersection, honoring client preference",
			offered:        []elliptic.Curve{elliptic.X25519, elliptic.P384},
			offeredPresent: true,
			wantRefuse:     false,
			wantCurve:      elliptic.P384,
		},
		{
			name:           "refuses a disjoint offered set",
			offered:        []elliptic.Curve{elliptic.X25519},
			offeredPresent: true,
			wantRefuse:     true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := &State{namedCurve: elliptic.P256} // default from flight0Generate
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

// TestFlight0ResumeIgnoresCurveConfig: a 1.2 session-resumption handshake reuses
// the cached master secret and never performs ECDHE, so the server's configured
// EllipticCurves must not be enforced against the resuming ClientHello. Modeled
// on TestSessionResume (server-side SessionStore path through handleHelloResume).
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
			EllipticCurves: []elliptic.Curve{elliptic.X25519}, // client offers only X25519
			MTU:            100,
		}
		c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), config, false)
		clientRes <- result{c, err}
	}()

	config := &Config{
		CipherSuites:   []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ServerName:     "example.com",
		SessionStore:   ss,
		EllipticCurves: []elliptic.Curve{elliptic.P256}, // server restricted to P-256 (disjoint from client)
		MTU:            100,
	}
	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true)
	// On HEAD this fails: flight0Parse rejects the disjoint curve set before
	// handleHelloResume can short-circuit, even though resumption uses no curve.
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

// TestFlight0PSKFallbackIgnoresCurveConfig: a client offering ECDHE_PSK + plain
// PSK (and therefore sending supported_groups) against a server that supports
// only plain PSK must complete the plain-PSK handshake. Plain PSK performs no
// ECDHE, so the server's configured EllipticCurves must not be enforced against
// the (irrelevant) offered curves.
func TestFlight0PSKFallbackIgnoresCurveConfig(t *testing.T) {
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
			// Offers ECDHE_PSK (so it advertises supported_groups) plus plain PSK.
			CipherSuites:   []CipherSuiteID{TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, TLS_PSK_WITH_AES_128_CCM_8},
			EllipticCurves: []elliptic.Curve{elliptic.X25519},
		}
		c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), config, false)
		clientRes <- result{c, err}
	}()

	config := &Config{
		PSK:             psk,
		PSKIdentityHint: []byte("hint"),
		// Server supports ONLY plain PSK — no ECDHE, needs no curve.
		CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		EllipticCurves: []elliptic.Curve{elliptic.P256}, // restricted, disjoint from the client's offer
	}
	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, false)
	// On HEAD this fails: flight0Parse rejects the disjoint supported_groups even
	// though the negotiated cipher suite (plain PSK) performs no ECDHE.
	assert.NoError(t, err)

	if err == nil {
		state, ok := server.ConnectionState()
		assert.True(t, ok)
		assert.Equal(t, TLS_PSK_WITH_AES_128_CCM_8, state.CipherSuiteID, "must have negotiated plain PSK, not ECDHE")
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
