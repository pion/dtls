// +build !js

package dtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
)

func TestContextConfig(t *testing.T) {
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
	addr := listen.LocalAddr().(*net.UDPAddr)

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	config := &Config{
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), 40*time.Millisecond)
		},
		Certificates: []tls.Certificate{cert},
	}

	dials := map[string]struct {
		f     func() (net.Conn, error)
		order []byte
	}{
		"Dial": {
			f: func() (net.Conn, error) {
				return Dial("udp", addr, config)
			},
			order: []byte{0, 1, 2},
		},
		"DialWithContext": {
			f: func() (net.Conn, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
				defer cancel()
				return DialWithContext(ctx, "udp", addr, config)
			},
			order: []byte{0, 2, 1},
		},
		"Client": {
			f: func() (net.Conn, error) {
				ca, _ := net.Pipe()
				defer func() {
					_ = ca.Close()
				}()
				return Client(ca, config)
			},
			order: []byte{0, 1, 2},
		},
		"ClientWithContext": {
			f: func() (net.Conn, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
				defer cancel()
				ca, _ := net.Pipe()
				defer func() {
					_ = ca.Close()
				}()
				return ClientWithContext(ctx, ca, config)
			},
			order: []byte{0, 2, 1},
		},
		"Server": {
			f: func() (net.Conn, error) {
				ca, _ := net.Pipe()
				defer func() {
					_ = ca.Close()
				}()
				return Server(ca, config)
			},
			order: []byte{0, 1, 2},
		},
		"ServerWithContext": {
			f: func() (net.Conn, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
				defer cancel()
				ca, _ := net.Pipe()
				defer func() {
					_ = ca.Close()
				}()
				return ServerWithContext(ctx, ca, config)
			},
			order: []byte{0, 2, 1},
		},
	}

	for name, dial := range dials {
		dial := dial
		t.Run(name, func(t *testing.T) {
			done := make(chan struct{})

			go func() {
				conn, err := dial.f()
				if err != errConnectTimeout {
					t.Errorf("Expected error: '%v', got: '%v'", errConnectTimeout, err)
					close(done)
					return
				}
				done <- struct{}{}
				_ = conn.Close()
			}()

			var order []byte
			early := time.After(30 * time.Millisecond)
			late := time.After(50 * time.Millisecond)
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
