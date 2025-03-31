// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

// Package udp implements DTLS specific UDP networking primitives.
package udp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v3/test"
	"github.com/stretchr/testify/assert"
)

var (
	errHandshakeFailed = errors.New("handshake failed")
	errUDPCastFailed   = fmt.Errorf("failed to cast listener Addr to *net.UDPAddr")
)

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
	t.Helper()

	listener, ca, cb, err := pipe()
	assert.NoError(t, err)

	defer func() {
		assert.NoError(t, ca.Close())
		assert.NoError(t, cb.Close())
		assert.NoError(t, listener.Close())
	}()

	opt := test.Options{
		MsgSize:  2048,
		MsgCount: 1, // Can't rely on UDP message order in CI
	}

	assert.NoError(t, test.StressDuplex(fromPC(ca, cb.LocalAddr()), cb, opt))
}

func TestListenerCloseTimeout(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	listener, ca, _, err := pipe()
	assert.NoError(t, err)

	assert.NoError(t, listener.Close())

	// Close client after server closes to cleanup
	assert.NoError(t, ca.Close())
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
	assert.NoError(t, err)

	for i := 0; i < backlog; i++ {
		aAddr, ok := listener.Addr().(*net.UDPAddr)
		assert.True(t, ok)
		conn, dErr := net.DialUDP(network, nil, aAddr)
		if dErr != nil {
			assert.Fail(t, "dial failed: %v", dErr)

			continue
		}
		_, wErr := conn.Write([]byte{byte(i)})
		assert.NoError(t, wErr)
		assert.NoError(t, conn.Close())
	}

	time.Sleep(100 * time.Millisecond) // Wait all packets being processed by readLoop

	// Unaccepted connections must be closed by listener.Close()
	assert.NoError(t, listener.Close())
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
			assert.NoError(t, err)

			var wgAcceptLoop sync.WaitGroup
			wgAcceptLoop.Add(1)
			defer func() {
				assert.NoError(t, listener.Close())
				wgAcceptLoop.Wait()
			}()
			aAddr, ok := listener.Addr().(*net.UDPAddr)
			assert.True(t, ok)
			conn, err := net.DialUDP(network, nil, aAddr)
			assert.NoError(t, err)

			_, err = conn.Write(testCase.packet)
			assert.NoError(t, err)

			defer func() {
				assert.NoError(t, conn.Close())
			}()

			chAccepted := make(chan struct{})
			go func() {
				defer wgAcceptLoop.Done()

				conn, _, aArr := listener.Accept()
				if aArr != nil {
					assert.ErrorIs(t, aArr, ErrClosedListener)

					return
				}
				close(chAccepted)
				assert.NoError(t, conn.Close())
			}()

			var accepted bool
			select {
			case <-chAccepted:
				accepted = true
			case <-time.After(10 * time.Millisecond):
			}

			assert.Equal(t, testCase.accept, accepted)
		})
	}
}

func TestListenerConcurrent(t *testing.T) { //nolint:gocyclo
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
	assert.NoError(t, err)

	for i := 0; i < backlog+1; i++ {
		addr, ok := listener.Addr().(*net.UDPAddr)
		assert.True(t, ok)
		conn, dErr := net.DialUDP(network, nil, addr)
		if dErr != nil {
			assert.Fail(t, "Failed to dial UDP: %v", dErr)

			continue
		}
		_, wErr := conn.Write([]byte{byte(i)})
		assert.NoError(t, wErr)
		assert.NoError(t, conn.Close())
	}

	time.Sleep(100 * time.Millisecond) // Wait all packets being processed by readLoop

	for i := 0; i < backlog; i++ {
		conn, _, lErr := listener.Accept()
		if lErr != nil {
			assert.Fail(t, "Failed to accept connection: %v", lErr)

			continue
		}
		b := make([]byte, 1)
		n, _, lErr := conn.ReadFrom(b)
		assert.NoError(t, lErr)
		assert.Equal(t, b[:n], []byte{byte(i)})
		assert.NoError(t, conn.Close())
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, _, lErr := listener.Accept()
		assert.ErrorIs(t, lErr, ErrClosedListener)
		if lErr == nil {
			assert.NoError(t, conn.Close())
		}
	}()

	time.Sleep(100 * time.Millisecond) // Last Accept should be discarded
	assert.NoError(t, listener.Close())

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
	dAddr, ok := listener.Addr().(*net.UDPAddr)
	if !ok {
		return nil, nil, nil, errUDPCastFailed
	}
	dConn, err = net.DialUDP(network, nil, dAddr)
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

func TestConnClose(t *testing.T) { //nolint:cyclop
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	t.Run("Close", func(t *testing.T) {
		// Check for leaking routines
		report := test.CheckRoutines(t)
		defer report()

		udpListener, ca, cb, errPipe := pipe()
		assert.NoError(t, errPipe)
		assert.NoError(t, ca.Close())
		assert.NoError(t, cb.Close())
		assert.NoError(t, udpListener.Close())
	})
	t.Run("CloseError1", func(t *testing.T) {
		// Check for leaking routines
		report := test.CheckRoutines(t)
		defer report()

		udpListener, ca, cb, errPipe := pipe()
		assert.NoError(t, errPipe)

		// Close l.pConn to inject error.
		listener, ok := udpListener.(*listener)
		assert.True(t, ok)
		assert.NoError(t, listener.pConn.Close())
		assert.NoError(t, cb.Close())
		assert.NoError(t, ca.Close())
		assert.Error(t, udpListener.Close())
	})
	t.Run("CloseError2", func(t *testing.T) {
		// Check for leaking routines
		report := test.CheckRoutines(t)
		defer report()

		l, ca, cb, errPipe := pipe()
		assert.NoError(t, errPipe)

		// Close l.pConn to inject error.
		listener, ok := l.(*listener)
		assert.True(t, ok)
		assert.NoError(t, listener.pConn.Close())
		assert.NoError(t, cb.Close())
		assert.NoError(t, l.Close())
		assert.Error(t, ca.Close())
	})
	t.Run("CancelRead", func(t *testing.T) {
		// Limit runtime in case of deadlocks
		lim := test.TimeOut(time.Second * 5)
		defer lim.Stop()

		// Check for leaking routines
		report := test.CheckRoutines(t)
		defer report()

		listener, ca, cb, errPipe := pipe()
		assert.NoError(t, errPipe)

		errC := make(chan error, 1)
		go func() {
			buf := make([]byte, 1024)
			// This read will block because we don't write on the other side.
			// Calling Close must unblock the call.
			_, _, err := ca.ReadFrom(buf)
			errC <- err
		}()

		assert.NoError(t, ca.Close()) // Trigger Read cancellation.

		// Main test condition, Read should return
		// after ca.Close() by closing the buffer.
		assert.ErrorIs(t, <-errC, io.EOF)
		assert.NoError(t, cb.Close())
		assert.NoError(t, listener.Close())
	})
}

func TestListenerCustomConnIDs(t *testing.T) { //nolint:gocyclo,cyclop,maintidx
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
	assert.NoError(t, err)

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
			assert.NoError(t, err)

			buf := make([]byte, 100)
			n, raddr, rErr := conn.ReadFrom(buf)
			assert.NoError(t, rErr)

			var udpPkt pkt
			assert.NoError(t, json.Unmarshal(buf[:n], &udpPkt))

			// First message should be a hello and custom connection
			// ID function will use remote address as identifier.
			assert.Equal(t, helloPayload, udpPkt.Payload)
			connID := udpPkt.ID

			// Send set message to associate ID with this connection.
			buf, err = json.Marshal(&pkt{
				ID:      connID,
				Payload: "set",
			})
			assert.NoError(t, err)

			_, wErr := conn.WriteTo(buf, raddr)
			assert.NoError(t, wErr)

			// Signal to the corresponding clients that connection ID has been
			// set.
			close(phaseOne[connID])
			// Receive packets, ensuring that each one came from a different
			// client remote address and has a unique payload.
			for j := 0; j < clientCount/serverCount; j++ {
				buf := make([]byte, 100)
				n, _, err := conn.ReadFrom(buf)
				assert.NoError(t, err)

				var udpPkt pkt
				assert.NoError(t, json.Unmarshal(buf[:n], &udpPkt))
				assert.Equal(t, connID, udpPkt.ID)

				// Ensure we only ever receive one message from a given client.
				clientMapMu.Lock()
				_, exists := clientMap[udpPkt.Payload]
				assert.Falsef(t, exists, "Multiple messages from single client %s", udpPkt.Payload)
				clientMap[udpPkt.Payload] = struct{}{}
				clientMapMu.Unlock()
			}
			assert.NoError(t, conn.Close())
		}()
	}

	// Start a client per server to send initial "hello" message and receive a
	// "set" message.
	for i := 0; i < serverCount; i++ {
		clientWg.Add(1)
		go func(connID int) {
			defer clientWg.Done()
			addr, ok := listener.Addr().(*net.UDPAddr)
			assert.True(t, ok)
			conn, dErr := net.DialUDP(network, nil, addr)
			assert.NoError(t, dErr)

			hbuf, err := json.Marshal(&pkt{
				ID:      connID,
				Payload: helloPayload,
			})
			assert.NoError(t, err)

			_, wErr := conn.Write(hbuf)
			assert.NoError(t, wErr)

			var udpPacket pkt
			buf := make([]byte, 100)
			n, err := conn.Read(buf)
			assert.NoError(t, err)

			assert.NoError(t, json.Unmarshal(buf[:n], &udpPacket))

			// Second message should be a set and custom connection identifier
			// function will update the connection ID from remote address to the
			// supplied ID.
			assert.Equal(t, "set", udpPacket.Payload)

			// Ensure the connection ID matches what the "hello" message
			// indicated.
			assert.Equal(t, connID, udpPacket.ID)

			// Close connection. We will reconnect from a different remote
			// address using the same connection ID.
			assert.NoError(t, conn.Close())
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
			addr, ok := listener.Addr().(*net.UDPAddr)
			assert.True(t, ok)
			conn, dErr := net.DialUDP(network, nil, addr)
			assert.NoError(t, dErr)

			// Send a packet with a connection ID and this client's local
			// address. The latter is used to identify this client as unique.
			buf, err := json.Marshal(&pkt{
				ID:      connID,
				Payload: conn.LocalAddr().String(),
			})
			assert.NoError(t, err)

			_, wErr := conn.Write(buf)
			assert.NoError(t, wErr)
			assert.NoError(t, conn.Close())
		}(i % serverCount)
	}

	// Wait for clients to exit.
	clientWg.Wait()
	// Wait for servers to exit.
	serverWg.Wait()
	assert.NoError(t, listener.Close())
}
