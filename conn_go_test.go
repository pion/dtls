// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

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
		f     func() (func() (net.Conn, error), func())
		order []byte
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
			order: []byte{0, 1, 2},
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
			order: []byte{0, 1, 2},
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
			order: []byte{0, 1, 2},
		},
	}

	for name, dial := range dials {
		dial := dial
		t.Run(name, func(t *testing.T) {
			done := make(chan struct{})

			go func() {
				d, cancel := dial.f()
				conn, err := d()
				defer cancel()
				var netError net.Error
				if !errors.As(err, &netError) || !netError.Temporary() { //nolint:staticcheck
					assert.Fail(t, "Dial failed with unexpected error", "err: %v", err)
					close(done)

					return
				}
				done <- struct{}{}
				if err == nil {
					_ = conn.Close()
				}
			}()

			var order []byte
			early := time.After(20 * time.Millisecond)
			late := time.After(60 * time.Millisecond)
			func() {
				for len(order) < 3 {
					select {
					case <-early:
						order = append(order, 0)
					case _, ok := <-done:
						if !ok {
							return
						}
						order = append(order, 1)
					case <-late:
						order = append(order, 2)
					}
				}
			}()
			assert.Equal(t, dial.order, order, "Invalid cancel timing")
		})
	}
}
