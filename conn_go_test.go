// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package dtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v3/dpipe"
	"github.com/pion/transport/v3/test"
)

func TestContextConfig(t *testing.T) { //nolint:cyclop
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	addrListen, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Dummy listener
	listen, err := net.ListenUDP("udp", addrListen)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer func() {
		_ = listen.Close()
	}()
	addr, ok := listen.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("Failed to cast net.UDPAddr")
	}

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	config := &Config{
		Certificates: []tls.Certificate{cert},
	}

	dials := map[string]struct {
		f     func() (func() (net.Conn, error), func())
		order []byte
	}{
		"Dial": {
			f: func() (func() (net.Conn, error), func()) {
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)

				return func() (net.Conn, error) {
						conn, err := Dial("udp", addr, config)
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
						conn, err := Client(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), config)
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
						conn, err := Server(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), config)
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
					t.Errorf("Client error exp(Temporary network error) failed(%v)", err)
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
			if !bytes.Equal(dial.order, order) {
				t.Errorf("Invalid cancel timing, expected: %v, got: %v", dial.order, order)
			}
		})
	}
}
