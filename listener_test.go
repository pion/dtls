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
	ln, done := setupHandshakingTest(t)
	defer ln.Close()

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
}

// TestSerialHandshakes tests that Accept uses serial handshakes.
// This ensures that the parallel handshake test actually proves changed behavior.
func TestSerialHandshakes(t *testing.T) {
	ln, _ := setupHandshakingTest(t)
	defer ln.Close()
	for idx := 0; idx < 2; idx++ {
		_, err := ln.Accept()
		if err == nil {
			t.Fatalf("Expected to fail accepting with timeout")
		}
	}
}

// setupHandshakingTest creates the setup for a handshaking test.
func setupHandshakingTest(t *testing.T) (ln net.Listener, done chan error) {
	lnAddr := &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
		Port: 5284,
	}
	config := &Config{
		PSK: func(b []byte) ([]byte, error) {
			return []byte("testpsk"), nil
		},
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), time.Second*2)
		},
		PSKIdentityHint: []byte("testhint"),
		CipherSuites:         []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		ExtendedMasterSecret: RequestExtendedMasterSecret,
	}

	ln, err := Listen("udp4", lnAddr, config)
	if err != nil {
		t.Fatalf("Failed creating listener: %s", err.Error())
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("Failed creating conn: %s", err.Error())
	}
	sleepyConn := sleepy{conn}

	conn, err = net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("Failed creating conn: %s", err.Error())
	}

	done = make(chan error)
	go doTestConn(sleepyConn, lnAddr, config, func(error){})
	time.Sleep(time.Second)
	go doTestConn(conn, lnAddr, config, func(err error) {
		done <- err
	})

	return ln, done
}

func doTestConn(
	inner net.PacketConn,
	lnAddr net.Addr,
	config *Config,
	onDone func(error),
) {
	conn, err := Client(inner, lnAddr, config)
	if err != nil {
		onDone(err)
		return
	}

	conn.Close()
	onDone(nil)
	return
}

type sleepy struct {
	net.PacketConn
}

func (s sleepy) ReadFrom(p []byte) (n int, add net.Addr, err error) {
	time.Sleep(time.Hour)
	return s.PacketConn.ReadFrom(p)
}
