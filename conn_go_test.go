// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package dtls

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v4/dpipe"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
)

func TestContextConfig(t *testing.T) { //nolint:cyclop
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	addrListen, err := net.ResolveUDPAddr("udp", "localhost:0")
	assert.NoError(t, err)

	// Dummy listener
	listen, err := net.ListenUDP("udp", addrListen)
	assert.NoError(t, err)
	defer func() {
		_ = listen.Close()
	}()
	addr, ok := listen.LocalAddr().(*net.UDPAddr)
	assert.True(t, ok)

	cert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	clientOpts := []ClientOption{
		WithCertificates(cert),
	}
	serverOpts := []ServerOption{
		WithCertificates(cert),
	}

	dials := map[string]struct {
		f func() (func() (net.Conn, error), func())
	}{
		"Dial": {
			f: func() (func() (net.Conn, error), func()) {
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)

				return func() (net.Conn, error) {
						conn, err := DialWithOptions("udp", addr, clientOpts...)
						if err != nil {
							return nil, err
						}

						return conn, conn.HandshakeContext(ctx)
					}, func() {
						cancel()
					}
			},
		},
		"Client": {
			f: func() (func() (net.Conn, error), func()) {
				ca, _ := dpipe.Pipe()
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)

				return func() (net.Conn, error) {
						conn, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), clientOpts...)
						if err != nil {
							return nil, err
						}

						return conn, conn.HandshakeContext(ctx)
					}, func() {
						_ = ca.Close()
						cancel()
					}
			},
		},
		"Server": {
			f: func() (func() (net.Conn, error), func()) {
				ca, _ := dpipe.Pipe()
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)

				return func() (net.Conn, error) {
						conn, err := ServerWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), serverOpts...)
						if err != nil {
							return nil, err
						}

						return conn, conn.HandshakeContext(ctx)
					}, func() {
						_ = ca.Close()
						cancel()
					}
			},
		},
	}

	type dialResult struct {
		err         error
		ok          bool
		completedAt time.Time
	}

	for name, dial := range dials {
		t.Run(name, func(t *testing.T) {
			done := make(chan dialResult, 1)
			startedAt := time.Now()

			go func() {
				d, cancel := dial.f()
				conn, err := d()
				defer cancel()
				var netError net.Error
				if err == nil {
					_ = conn.Close()
				}

				done <- dialResult{
					err:         err,
					ok:          errors.As(err, &netError) && netError.Temporary(), //nolint:staticcheck
					completedAt: time.Now(),
				}
			}()

			const earlyCancelWindow = 20 * time.Millisecond
			time.Sleep(earlyCancelWindow)

			assertResult := func(result dialResult) {
				assert.GreaterOrEqual(
					t,
					result.completedAt.Sub(startedAt),
					earlyCancelWindow,
					"Invalid cancel timing",
				)
				if !result.ok {
					assert.Fail(t, "Dial failed with unexpected error", "err: %v", result.err)
				}
			}

			select {
			case result := <-done:
				assertResult(result)

				return
			default:
			}

			select {
			case result := <-done:
				assertResult(result)
			case <-time.After(time.Second):
				assert.Fail(t, "Dial did not finish after context cancellation")
			}
		})
	}
}
