package e2e

import (
	"io"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pions/dtls"
)

const testMessage = "Hello World"
const serverPort = 5555
const testTimeLimit = 5 * time.Second
const messageRetry = 200 * time.Millisecond

// Counter to make sure both sides got a message
var messageRecvCount uint64

func simpleReadWrite(errChan chan error, outChan chan string, conn io.ReadWriteCloser, listener io.Closer) {
	go func() {
		buffer := make([]byte, 8192)
		n, err := conn.Read(buffer)
		if err != nil {
			errChan <- err
			return
		}

		outChan <- string(buffer[:n])
		atomic.AddUint64(&messageRecvCount, 1)
	}()

	for {
		if atomic.LoadUint64(&messageRecvCount) == 2 {
			break
		} else if _, err := conn.Write([]byte(testMessage)); err != nil {
			errChan <- err
			break
		}

		time.Sleep(messageRetry)
	}

	maybePushError := func(err error) {
		select {
		case errChan <- err: // Do we care about these errors?
		default:
		}
	}

	if listener != nil {
		maybePushError(listener.Close())
	}
	maybePushError(conn.Close())
}

/*
  Simple DTLS Client/Server can communicate
    - Assert that you can send messages both ways
	- Assert that Close() on both ends work
	- Assert that no Goroutines are leaked
*/
func TestPionE2ESimple(t *testing.T) {
	expectedGoRoutineCount := runtime.NumGoroutine()
	errChan := make(chan error)
	clientChan := make(chan string)
	serverChan := make(chan string)

	cert, key, err := dtls.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	// DTLS Client
	go func() {
		conn, err := dtls.Dial("udp",
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
			&dtls.Config{Certificate: cert, PrivateKey: key},
		)
		if err != nil {
			errChan <- err
			return
		}
		simpleReadWrite(errChan, clientChan, conn, nil)
	}()

	// DTLS Server
	go func() {
		listener, err := dtls.Listen("udp",
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
			&dtls.Config{Certificate: cert, PrivateKey: key},
		)
		if err != nil {
			errChan <- err
			return
		}
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}

		simpleReadWrite(errChan, serverChan, conn, listener)
	}()

	func() {
		seenClient, seenServer := false, false
		for {
			select {
			case err := <-errChan:
				t.Fatal(err)
			case <-time.After(testTimeLimit):
				t.Fatalf("Test timeout, seenClient %t seenServer %t", seenClient, seenServer)
			case clientMsg := <-clientChan:
				if clientMsg != testMessage {
					t.Fatalf("clientMsg does not equal test message: %s %s", clientMsg, testMessage)
				}

				seenClient = true
				if seenClient && seenServer {
					return
				}
			case serverMsg := <-serverChan:
				if serverMsg != testMessage {
					t.Fatalf("serverMsg does not equal test message: %s %s", serverMsg, testMessage)
				}

				seenServer = true
				if seenClient && seenServer {
					return
				}
			}
		}
	}()

	// We have seen Client+Server communication! Now count goroutines to make sure we haven't leaked
	time.Sleep(time.Second) // TODO racey
	goRoutineCount := runtime.NumGoroutine()
	if goRoutineCount != expectedGoRoutineCount {
		if err := pprof.Lookup("goroutine").WriteTo(os.Stderr, 1); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("goRoutineCount != expectedGoRoutineCount, possible leak: %d %d", goRoutineCount, expectedGoRoutineCount)
	}
}
