package dtls

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestParallelHandshakes tests that handshakes can be performed in parallel
// using the AcceptHandshake method.
// We create 2 connections to a listener.
// The first is "sleepy", it takes a while to read or write.
// The second is normal.
// We should quickly complete a handshake with the second and start reading.
func TestParallelHandshakes(t *testing.T) {
	done := make(chan error)
	doHandshakingTest(
		t, 5284,
		func(inner net.PacketConn, ln net.Listener, config *Config) {
			Client(inner, ln.Addr(), config)
		},
		func(inner net.PacketConn, ln net.Listener, config *Config) {
			conn, err := Client(inner, ln.Addr(), config)
			if err != nil {
				done <- err
				return
			}

			conn.Close()
			done <- nil
		},
		func(ln net.Listener) {
			type AcceptHandshaker interface {
				AcceptHandshake() (Handshaker, error)
			}

			for idx := 0; idx < 2; idx++ {
				hs, err := ln.(AcceptHandshaker).AcceptHandshake()
				if err != nil {
					t.Fatalf("Failed accepting: %s", err.Error())
				}
				go hs.Handshake()
			}

			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(time.Millisecond*100):
				t.Errorf("Expected second connection to handshake quickly")
			}
		},
	)
}

// TestSerialHandshakes tests that Accept uses serial handshakes.
// This ensures that the parallel handshake test actually proves changed behavior.
func TestSerialHandshakes(t *testing.T) {
	doHandshakingTest(
		t, 5284,
		func(inner net.PacketConn, ln net.Listener, config *Config) {
			Client(inner, ln.Addr(), config)
		},
		func(inner net.PacketConn, ln net.Listener, config *Config) {
			Client(inner, ln.Addr(), config)
		},
		func(ln net.Listener) {
			_, err := ln.Accept()
			if err == nil {
				t.Errorf("Expected to time out, but succeeded")
			}
		},
	)
}

// setupHandshakingTest creates the setup for a handshaking test.
func doHandshakingTest(
	t *testing.T,
	port int,
	sleepyConnHandler func(conn net.PacketConn, ln net.Listener, config *Config),
	normalConnHandler func(conn net.PacketConn, ln net.Listener, config *Config),
	finisher func(ln net.Listener),
) {
	lnAddr := &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
		Port: port,
	}
	config := &Config{
		PSK: func(b []byte) ([]byte, error) {
			return []byte("testpsk"), nil
		},
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), time.Millisecond*200)
		},
		PSKIdentityHint: []byte("testhint"),
		CipherSuites:         []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		ExtendedMasterSecret: RequestExtendedMasterSecret,
	}

	ln, err := Listen("udp4", lnAddr, config)
	if err != nil {
		t.Fatalf("Failed creating listener: %s", err.Error())
	}
	defer ln.Close()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("Failed creating conn: %s", err.Error())
	}
	sleepyConn := sleepy{conn}
	go sleepyConnHandler(sleepyConn, ln, config)
	time.Sleep(time.Millisecond * 100)

	conn, err = net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("Failed creating conn: %s", err.Error())
	}
	go normalConnHandler(conn, ln, config)
	finisher(ln)

	return
}

type sleepy struct {
	net.PacketConn
}

func (s sleepy) ReadFrom(p []byte) (n int, add net.Addr, err error) {
	time.Sleep(time.Hour)
	return s.PacketConn.ReadFrom(p)
}
