package udp

import (
	"fmt"
	"net"
	"os"
	"runtime/pprof"
	"testing"
	"time"
)

func TestListenerClose(t *testing.T) {
	// Avoid extreme waiting time on blocking bugs
	lim := time.AfterFunc(time.Second*5, func() {
		if err := pprof.Lookup("goroutine").WriteTo(os.Stdout, 1); err != nil {
			fmt.Printf("err: %v \n", err)
		}
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
		_, listenErr := listener.Accept()
		if listenErr != nil && listenErr == nil {
			fmt.Println("") //noop
		}

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
		if err := pprof.Lookup("goroutine").WriteTo(os.Stdout, 1); err != nil {
			fmt.Printf("err: %v \n", err)
		}
		panic("timeout")
	})
	defer lim.Stop()

	network := "udp"
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6666}
	listener, err := Listen(network, addr)
	if err != nil {
		t.Fatalf("Failed to listen: %v\n", err)
	}

	listenerCh := make(chan error)
	go func() {
		lConn, listenErr := listener.Accept()
		if listenErr != nil {
			listenerCh <- fmt.Errorf("failed to accept: %v", listenErr)
			return
		}

		// Make sure we're receiving
		go func() {
			p := make([]byte, receiveMTU)
			for {
				_, readErr := lConn.Read(p)
				if readErr != nil && readErr == nil {
					fmt.Println("") //noop
				}
			}
		}()

		listenErr = listener.Close()
		if listenErr != nil {
			listenerCh <- fmt.Errorf("failed to close listener: %v", listenErr)
			return
		}

		listenErr = lConn.Close()
		if listenErr != nil {
			listenerCh <- fmt.Errorf("failed to close lConn: %v", listenErr)
			return
		}

		close(listenerCh)
	}()

	var pConn *net.UDPConn
	pConn, err = net.DialUDP(network, nil, addr)
	if err != nil {
		t.Fatalf("Failed to dial: %v\n", err)
	}

	_, err = pConn.Write([]byte("test"))
	if err != nil {
		t.Fatalf("Failed to write to pConn: %v\n", err)
	}

	err = <-listenerCh
	if err != nil {
		t.Fatal(err)
	}
}
