// +build !js

package udp

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/transport/test"
)

// Note: doesn't work since closing isn't propagated to the other side
//func TestNetTest(t *testing.T) {
//	lim := test.TimeOut(time.Minute*1 + time.Second*10)
//	defer lim.Stop()
//
//	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
//		listener, c1, c2, err = pipe()
//		if err != nil {
//			return nil, nil, nil, err
//		}
//		stop = func() {
//			c1.Close()
//			c2.Close()
//			listener.Close(1 * time.Second)
//		}
//		return
//	})
//}

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

func stressDuplex(t *testing.T) {
	listener, ca, cb, err := pipe()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = ca.Close()
		if err != nil {
			t.Fatal(err)
		}
		err = cb.Close()
		if err != nil {
			t.Fatal(err)
		}
		err = listener.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	opt := test.Options{
		MsgSize:  2048,
		MsgCount: 1, // Can't rely on UDP message order in CI
	}

	err = test.StressDuplex(ca, cb, opt)
	if err != nil {
		t.Fatal(err)
	}
}

func TestListenerCloseTimeout(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
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
		conn, derr := net.DialUDP(network, nil, listener.Addr().(*net.UDPAddr))
		if derr != nil {
			t.Error(derr)
			continue
		}
		if _, werr := conn.Write([]byte{byte(i)}); werr != nil {
			t.Error(werr)
		}
		if cerr := conn.Close(); cerr != nil {
			t.Error(cerr)
		}
	}

	time.Sleep(100 * time.Millisecond) // Wait all packets being processed by readLoop

	// Unaccepted connections must be closed by listener.Close()
	err = listener.Close()
	if err != nil {
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
				cerr := listener.Close()
				if cerr != nil {
					t.Fatal(cerr)
				}
				wgAcceptLoop.Wait()
			}()

			conn, derr := net.DialUDP(network, nil, listener.Addr().(*net.UDPAddr))
			if derr != nil {
				t.Fatal(derr)
			}
			if _, werr := conn.Write(testCase.packet); werr != nil {
				t.Fatal(werr)
			}
			defer func() {
				if cerr := conn.Close(); cerr != nil {
					t.Error(cerr)
				}
			}()

			chAccepted := make(chan struct{})
			go func() {
				defer wgAcceptLoop.Done()

				conn, aerr := listener.Accept()
				if aerr != nil {
					if aerr != errClosedListener {
						t.Error(aerr)
					}
					return
				}
				close(chAccepted)
				if cerr := conn.Close(); cerr != nil {
					t.Error(cerr)
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
		conn, derr := net.DialUDP(network, nil, listener.Addr().(*net.UDPAddr))
		if derr != nil {
			t.Error(derr)
			continue
		}
		if _, werr := conn.Write([]byte{byte(i)}); werr != nil {
			t.Error(werr)
		}
		if cerr := conn.Close(); cerr != nil {
			t.Error(cerr)
		}
	}

	time.Sleep(100 * time.Millisecond) // Wait all packets being processed by readLoop

	for i := 0; i < backlog; i++ {
		conn, aerr := listener.Accept()
		if aerr != nil {
			t.Error(aerr)
			continue
		}
		b := make([]byte, 1)
		n, rerr := conn.Read(b)
		if rerr != nil {
			t.Error(rerr)
		} else if !bytes.Equal([]byte{byte(i)}, b[:n]) {
			t.Errorf("Packet from connection %d is wrong, expected: [%d], got: %v", i, i, b[:n])
		}
		if err = conn.Close(); err != nil {
			t.Error(err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if conn, aerr := listener.Accept(); aerr != errClosedListener {
			t.Errorf("Connection exceeding backlog limit must be discarded: %v", aerr)
			if aerr == nil {
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

func pipe() (net.Listener, net.Conn, *net.UDPConn, error) {
	// Start listening
	network, addr := getConfig()
	listener, err := Listen(network, addr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to listen: %v", err)
	}

	// Open a connection
	var dConn *net.UDPConn
	dConn, err = net.DialUDP(network, nil, listener.Addr().(*net.UDPAddr))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to dial: %v", err)
	}

	// Write to the connection to initiate it
	handshake := "hello"
	_, err = dConn.Write([]byte(handshake))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to write to dialed Conn: %v", err)
	}

	// Accept the connection
	var lConn net.Conn
	lConn, err = listener.Accept()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to accept Conn: %v", err)
	}

	buf := make([]byte, len(handshake))
	n := 0
	n, err = lConn.Read(buf)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read handshake: %v", err)
	}

	result := string(buf[:n])
	if handshake != result {
		return nil, nil, nil, fmt.Errorf("handshake failed: %s != %s", handshake, result)
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
		if err := l.(*listener).pConn.Close(); err != nil {
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
		if err := l.(*listener).pConn.Close(); err != nil {
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
}
