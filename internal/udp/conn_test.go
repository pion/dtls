package udp

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pions/transport/test"
)

// Note: doesn't work since closing isn't propagated to the other side
//func TestNetTest(t *testing.T) {
//	lim := test.TimeOut(time.Minute*1 + time.Second*10)
//	defer lim.Stop()
//
//	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
//		c1, c2, err = pipe()
//		if err != nil {
//			return nil, nil, nil, err
//		}
//		stop = func() {
//			c1.Close()
//			c2.Close()
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
	ca, cb, err := pipe()
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

func pipe() (*Conn, *net.UDPConn, error) {
	// Start listening
	network, addr := getConfig()
	listener, err := Listen(network, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen: %v", err)
	}

	// Open a connection
	var dConn *net.UDPConn
	dConn, err = net.DialUDP(network, nil, listener.Addr().(*net.UDPAddr))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial: %v", err)
	}

	// Write to the connection to initiate it
	handshake := "hello"
	_, err = dConn.Write([]byte(handshake))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to write to dialed Conn: %v", err)
	}

	// Accept the connection
	var lConn *Conn
	lConn, err = listener.Accept()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to accept Conn: %v", err)
	}

	buf := make([]byte, len(handshake))
	n := 0
	n, err = lConn.Read(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read handshake: %v", err)
	}

	result := string(buf[:n])
	if handshake != result {
		return nil, nil, fmt.Errorf("handshake failed: %s != %s", handshake, result)
	}

	// Close the listener
	err = listener.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("failed close listener: %v", err)
	}

	return lConn, dConn, nil
}

func getConfig() (string, *net.UDPAddr) {
	return "udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

// func TestConnClose(t *testing.T) {
// 	lim := test.TimeOut(time.Second * 5)
// 	defer lim.Stop()
//
// 	ca, cb, err := pipe()
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	err = ca.Close()
// 	if err != nil {
// 		t.Fatalf("Failed to close A side: %v\n", err)
// 	}
// 	err = cb.Close()
// 	if err != nil {
// 		t.Fatalf("Failed to close B side: %v\n", err)
// 	}
// }
