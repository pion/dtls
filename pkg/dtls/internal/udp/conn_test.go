package udp

import (
	"net"
	"os"
	"runtime/pprof"
	"testing"
	"time"
)

func TestListenerClose(t *testing.T) {
	// Avoid extreme waiting time on blocking bugs
	lim := time.AfterFunc(time.Second*5, func() {
		pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
		panic("timeout")
	})
	defer lim.Stop()

	network := "udp"
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6666}
	listener, err := Listen(network, addr)
	if err != nil {
		t.Fatalf("Failed to listen: %v\n", err)
	}

	done := make(chan struct{})
	go func() {
		_, _ = listener.Accept()

		close(done)
	}()

	err = listener.Close()
	if err != nil {
		t.Fatalf("Failed to close listener: %v\n", err)
	}

	<-done
}

func TestConnClose(t *testing.T) {
	// Avoid extreme waiting time on blocking bugs
	lim := time.AfterFunc(time.Second*5, func() {
		pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
		panic("timeout")
	})
	defer lim.Stop()

	network := "udp"
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6666}
	listener, err := Listen(network, addr)
	if err != nil {
		t.Fatalf("Failed to listen: %v\n", err)
	}

	done := make(chan struct{})
	go func() {
		lConn, err := listener.Accept()
		if err != nil {
			t.Fatalf("Failed to accept: %v\n", err)
		}

		// Make sure we're receiving
		go func() {
			p := make([]byte, receiveMTU)
			for {
				_, _ = lConn.Read(p)
			}
		}()

		err = listener.Close()
		if err != nil {
			t.Fatalf("Failed to close listener: %v\n", err)
		}

		err = lConn.Close()
		if err != nil {
			t.Fatalf("Failed to close lConn: %v\n", err)
		}

		close(done)
	}()

	pConn, err := net.DialUDP(network, nil, addr)
	if err != nil {
		t.Fatalf("Failed to dial: %v\n", err)
	}

	_, err = pConn.Write([]byte("test"))
	if err != nil {
		t.Fatalf("Failed to write to pConn: %v\n", err)
	}

	<-done
}
