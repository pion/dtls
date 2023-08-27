// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

// Package udp implements DTLS specific UDP networking primitives.
package udp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	dtlsnet "github.com/pion/dtls/v2/pkg/net"
	"github.com/pion/transport/v2/test"
)

var errHandshakeFailed = errors.New("handshake failed")

func TestStressDuplex(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	// Run the test
	stressDuplex(t)
}

type rw struct {
	p     net.PacketConn
	raddr net.Addr
}

func fromPC(p net.PacketConn, raddr net.Addr) *rw {
	return &rw{
		p:     p,
		raddr: raddr,
	}
}

func (r *rw) Read(p []byte) (int, error) {
	n, _, err := r.p.ReadFrom(p)
	return n, err
}

func (r *rw) Write(p []byte) (int, error) {
	return r.p.WriteTo(p, r.raddr)
}

func stressDuplex(t *testing.T) {
	listener, ca, cb, err := pipe()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if ca.Close() != nil {
			t.Fatal(err)
		}
		if cb.Close() != nil {
			t.Fatal(err)
		}
		if listener.Close() != nil {
			t.Fatal(err)
		}
	}()

	opt := test.Options{
		MsgSize:  2048,
		MsgCount: 1, // Can't rely on UDP message order in CI
	}

	if err := test.StressDuplex(fromPC(ca, cb.LocalAddr()), cb, opt); err != nil {
		t.Fatal(err)
	}
}

func TestListenerCloseTimeout(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	listener, ca, _, err := pipe()
	if err != nil {
		t.Fatal(err)
	}

	err = listener.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Close client after server closes to cleanup
	err = ca.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestListenerCloseUnaccepted(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	const backlog = 2

	network, addr := getConfig()
	listener, err := (&ListenConfig{
		Backlog: backlog,
	}).Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < backlog; i++ {
		conn, dErr := net.DialUDP(network, nil, listener.Addr().(*net.UDPAddr))
		if dErr != nil {
			t.Error(dErr)
			continue
		}
		if _, wErr := conn.Write([]byte{byte(i)}); wErr != nil {
			t.Error(wErr)
		}
		if cErr := conn.Close(); cErr != nil {
			t.Error(cErr)
		}
	}

	time.Sleep(100 * time.Millisecond) // Wait all packets being processed by readLoop

	// Unaccepted connections must be closed by listener.Close()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListenerAcceptFilter(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	testCases := map[string]struct {
		packet []byte
		accept bool
	}{
		"CreateConn": {
			packet: []byte{0xAA},
			accept: true,
		},
		"Discarded": {
			packet: []byte{0x00},
			accept: false,
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			network, addr := getConfig()
			listener, err := (&ListenConfig{
				AcceptFilter: func(pkt []byte) bool {
					return pkt[0] == 0xAA
				},
			}).Listen(network, addr)
			if err != nil {
				t.Fatal(err)
			}

			var wgAcceptLoop sync.WaitGroup
			wgAcceptLoop.Add(1)
			defer func() {
				if lErr := listener.Close(); lErr != nil {
					t.Fatal(lErr)
				}
				wgAcceptLoop.Wait()
			}()

			conn, err := net.DialUDP(network, nil, listener.Addr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(testCase.packet); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := conn.Close(); err != nil {
					t.Error(err)
				}
			}()

			chAccepted := make(chan struct{})
			go func() {
				defer wgAcceptLoop.Done()

				conn, _, aArr := listener.Accept()
				if aArr != nil {
					if !errors.Is(aArr, ErrClosedListener) {
						t.Error(aArr)
					}
					return
				}
				close(chAccepted)
				if err := conn.Close(); err != nil {
					t.Error(err)
				}
			}()

			var accepted bool
			select {
			case <-chAccepted:
				accepted = true
			case <-time.After(10 * time.Millisecond):
			}

			if accepted != testCase.accept {
				if testCase.accept {
					t.Error("Packet should create new conn")
				} else {
					t.Error("Packet should not create new conn")
				}
			}
		})
	}
}

func TestListenerConcurrent(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	const backlog = 2

	network, addr := getConfig()
	listener, err := (&ListenConfig{
		Backlog: backlog,
	}).Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < backlog+1; i++ {
		conn, dErr := net.DialUDP(network, nil, listener.Addr().(*net.UDPAddr))
		if dErr != nil {
			t.Error(dErr)
			continue
		}
		if _, wErr := conn.Write([]byte{byte(i)}); wErr != nil {
			t.Error(wErr)
		}
		if cErr := conn.Close(); cErr != nil {
			t.Error(cErr)
		}
	}

	time.Sleep(100 * time.Millisecond) // Wait all packets being processed by readLoop

	for i := 0; i < backlog; i++ {
		conn, _, lErr := listener.Accept()
		if lErr != nil {
			t.Error(lErr)
			continue
		}
		b := make([]byte, 1)
		n, _, lErr := conn.ReadFrom(b)
		if lErr != nil {
			t.Error(lErr)
		} else if !bytes.Equal([]byte{byte(i)}, b[:n]) {
			t.Errorf("Packet from connection %d is wrong, expected: [%d], got: %v", i, i, b[:n])
		}
		if lErr = conn.Close(); lErr != nil {
			t.Error(lErr)
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if conn, _, lErr := listener.Accept(); !errors.Is(lErr, ErrClosedListener) {
			t.Errorf("Connection exceeding backlog limit must be discarded: %v", lErr)
			if lErr == nil {
				_ = conn.Close()
			}
		}
	}()

	time.Sleep(100 * time.Millisecond) // Last Accept should be discarded
	err = listener.Close()
	if err != nil {
		t.Fatal(err)
	}

	wg.Wait()
}

func pipe() (dtlsnet.PacketListener, net.PacketConn, *net.UDPConn, error) {
	// Start listening
	network, addr := getConfig()
	listener, err := Listen(network, addr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to listen: %w", err)
	}

	// Open a connection
	var dConn *net.UDPConn
	dConn, err = net.DialUDP(network, nil, listener.Addr().(*net.UDPAddr))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to dial: %w", err)
	}

	// Write to the connection to initiate it
	handshake := "hello"
	_, err = dConn.Write([]byte(handshake))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to write to dialed Conn: %w", err)
	}

	// Accept the connection
	var lConn net.PacketConn
	lConn, _, err = listener.Accept()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to accept Conn: %w", err)
	}

	var n int
	buf := make([]byte, len(handshake))
	if n, _, err = lConn.ReadFrom(buf); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read handshake: %w", err)
	}

	result := string(buf[:n])
	if handshake != result {
		return nil, nil, nil, fmt.Errorf("%w: %s != %s", errHandshakeFailed, handshake, result)
	}

	return listener, lConn, dConn, nil
}

func getConfig() (string, *net.UDPAddr) {
	return "udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func TestConnClose(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	t.Run("Close", func(t *testing.T) {
		// Check for leaking routines
		report := test.CheckRoutines(t)
		defer report()

		l, ca, cb, errPipe := pipe()
		if errPipe != nil {
			t.Fatal(errPipe)
		}
		if err := ca.Close(); err != nil {
			t.Errorf("Failed to close A side: %v", err)
		}
		if err := cb.Close(); err != nil {
			t.Errorf("Failed to close B side: %v", err)
		}
		if err := l.Close(); err != nil {
			t.Errorf("Failed to close listener: %v", err)
		}
	})
	t.Run("CloseError1", func(t *testing.T) {
		// Check for leaking routines
		report := test.CheckRoutines(t)
		defer report()

		l, ca, cb, errPipe := pipe()
		if errPipe != nil {
			t.Fatal(errPipe)
		}
		// Close l.pConn to inject error.
		if err := l.(*listener).pConn.Close(); err != nil { //nolint:forcetypeassert
			t.Error(err)
		}

		if err := cb.Close(); err != nil {
			t.Errorf("Failed to close A side: %v", err)
		}
		if err := ca.Close(); err != nil {
			t.Errorf("Failed to close B side: %v", err)
		}
		if err := l.Close(); err == nil {
			t.Errorf("Error is not propagated to Listener.Close")
		}
	})
	t.Run("CloseError2", func(t *testing.T) {
		// Check for leaking routines
		report := test.CheckRoutines(t)
		defer report()

		l, ca, cb, errPipe := pipe()
		if errPipe != nil {
			t.Fatal(errPipe)
		}
		// Close l.pConn to inject error.
		if err := l.(*listener).pConn.Close(); err != nil { //nolint:forcetypeassert
			t.Error(err)
		}

		if err := cb.Close(); err != nil {
			t.Errorf("Failed to close A side: %v", err)
		}
		if err := l.Close(); err != nil {
			t.Errorf("Failed to close listener: %v", err)
		}
		if err := ca.Close(); err == nil {
			t.Errorf("Error is not propagated to Conn.Close")
		}
	})
	t.Run("CancelRead", func(t *testing.T) {
		// Limit runtime in case of deadlocks
		lim := test.TimeOut(time.Second * 5)
		defer lim.Stop()

		// Check for leaking routines
		report := test.CheckRoutines(t)
		defer report()

		l, ca, cb, errPipe := pipe()
		if errPipe != nil {
			t.Fatal(errPipe)
		}

		errC := make(chan error, 1)
		go func() {
			buf := make([]byte, 1024)
			// This read will block because we don't write on the other side.
			// Calling Close must unblock the call.
			_, _, err := ca.ReadFrom(buf)
			errC <- err
		}()

		if err := ca.Close(); err != nil { // Trigger Read cancellation.
			t.Errorf("Failed to close B side: %v", err)
		}

		// Main test condition, Read should return
		// after ca.Close() by closing the buffer.
		if err := <-errC; !errors.Is(err, io.EOF) {
			t.Errorf("expected err to be io.EOF but got %v", err)
		}

		if err := cb.Close(); err != nil {
			t.Errorf("Failed to close A side: %v", err)
		}
		if err := l.Close(); err != nil {
			t.Errorf("Failed to close listener: %v", err)
		}
	})
}

func TestListenerCustomConnIDs(t *testing.T) {
	const helloPayload, setPayload = "hello", "set"
	const serverCount, clientCount = 5, 20
	// Limit runtime in case of deadlocks.
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines.
	report := test.CheckRoutines(t)
	defer report()

	type pkt struct {
		ID      int
		Payload string
	}
	network, addr := getConfig()
	listener, err := (&ListenConfig{
		// For all datagrams other than the initial "hello" packet, use the ID
		// to route.
		DatagramRouter: func(buf []byte) (string, bool) {
			var p pkt
			if err := json.Unmarshal(buf, &p); err != nil {
				return "", false
			}
			if p.Payload == helloPayload {
				return "", false
			}
			return fmt.Sprint(p.ID), true
		},
		// Use the outgoing "set" payload to add an identifier for a connection.
		ConnectionIdentifier: func(buf []byte) (string, bool) {
			var p pkt
			if err := json.Unmarshal(buf, &p); err != nil {
				return "", false
			}
			if p.Payload == setPayload {
				return fmt.Sprint(p.ID), true
			}
			return "", false
		},
	}).Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}

	var clientWg sync.WaitGroup
	var phaseOne [5]chan struct{}
	for i := range phaseOne {
		phaseOne[i] = make(chan struct{})
	}
	var serverWg sync.WaitGroup
	clientMap := map[string]struct{}{}
	var clientMapMu sync.Mutex
	// Start servers.
	for i := 0; i < serverCount; i++ {
		serverWg.Add(1)
		go func() {
			defer serverWg.Done()
			// The first payload from the accepted connection should inform
			// which connection this server is.
			conn, _, err := listener.Accept()
			if err != nil {
				t.Error(err)
				return
			}
			buf := make([]byte, 100)
			n, raddr, rErr := conn.ReadFrom(buf)
			if rErr != nil {
				t.Error(err)
				return
			}
			var p pkt
			if uErr := json.Unmarshal(buf[:n], &p); uErr != nil {
				t.Error(err)
				return
			}
			// First message should be a hello and custom connection
			// ID function will use remote address as identifier.
			if p.Payload != helloPayload {
				t.Error("Expected hello message")
				return
			}
			connID := p.ID

			// Send set message to associate ID with this connection.
			buf, err = json.Marshal(&pkt{
				ID:      connID,
				Payload: "set",
			})
			if err != nil {
				t.Error(err)
				return
			}
			if _, wErr := conn.WriteTo(buf, raddr); wErr != nil {
				t.Error(wErr)
				return
			}
			// Signal to the corresponding clients that connection ID has been
			// set.
			close(phaseOne[connID])
			// Receive packets, ensuring that each one came from a different
			// client remote address and has a unique payload.
			for j := 0; j < clientCount/serverCount; j++ {
				buf := make([]byte, 100)
				n, _, err := conn.ReadFrom(buf)
				if err != nil {
					t.Error(err)
					return
				}
				var p pkt
				if err := json.Unmarshal(buf[:n], &p); err != nil {
					t.Error(err)
					return
				}
				if p.ID != connID {
					t.Errorf("Expected connection ID %d, but got %d", connID, p.ID)
					return
				}
				// Ensure we only ever receive one message from
				// a given client.
				clientMapMu.Lock()
				if _, ok := clientMap[p.Payload]; ok {
					t.Errorf("Multiple messages from single client %s", p.Payload)
					return
				}
				clientMap[p.Payload] = struct{}{}
				clientMapMu.Unlock()
			}
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		}()
	}

	// Start a client per server to send initial "hello" message and receive a
	// "set" message.
	for i := 0; i < serverCount; i++ {
		clientWg.Add(1)
		go func(connID int) {
			defer clientWg.Done()
			conn, dErr := net.DialUDP(network, nil, listener.Addr().(*net.UDPAddr))
			if dErr != nil {
				t.Error(dErr)
				return
			}
			hbuf, err := json.Marshal(&pkt{
				ID:      connID,
				Payload: helloPayload,
			})
			if err != nil {
				t.Error(err)
				return
			}
			if _, wErr := conn.Write(hbuf); wErr != nil {
				t.Error(wErr)
				return
			}

			var p pkt
			buf := make([]byte, 100)
			n, err := conn.Read(buf)
			if err != nil {
				t.Error(err)
				return
			}
			if err := json.Unmarshal(buf[:n], &p); err != nil {
				t.Error(err)
				return
			}
			// Second message should be a set and custom connection identifier
			// function will update the connection ID from remote address to the
			// supplied ID.
			if p.Payload != "set" {
				t.Error("Expected set message")
				return
			}
			// Ensure the connection ID matches what the "hello" message
			// indicated.
			if p.ID != connID {
				t.Errorf("Expected connection ID %d, but got %d", connID, p.ID)
				return
			}
			// Close connection. We will reconnect from a different remote
			// address using the same connection ID.
			if cErr := conn.Close(); cErr != nil {
				t.Error(cErr)
			}
		}(i)
	}

	// Spawn clients sending to server connections.
	for i := 1; i <= clientCount; i++ {
		clientWg.Add(1)
		go func(connID int) {
			defer clientWg.Done()
			// Ensure that we are using a connection ID for packet
			// routing prior to sending any messages.
			<-phaseOne[connID]
			conn, dErr := net.DialUDP(network, nil, listener.Addr().(*net.UDPAddr))
			if dErr != nil {
				t.Error(dErr)
				return
			}
			// Send a packet with a connection ID and this client's local
			// address. The latter is used to identify this client as unique.
			buf, err := json.Marshal(&pkt{
				ID:      connID,
				Payload: conn.LocalAddr().String(),
			})
			if err != nil {
				t.Error(err)
				return
			}
			if _, wErr := conn.Write(buf); wErr != nil {
				t.Error(wErr)
				return
			}
			if cErr := conn.Close(); cErr != nil {
				t.Error(cErr)
			}
		}(i % serverCount)
	}

	// Wait for clients to exit.
	clientWg.Wait()
	// Wait for servers to exit.
	serverWg.Wait()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}
