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

	"github.com/pion/dtls"
)

const testMessage = "Hello World"
const testTimeLimit = 5 * time.Second
const messageRetry = 200 * time.Millisecond

func simpleReadWrite(errChan chan error, outChan chan string, conn io.ReadWriteCloser, listener io.Closer, messageRecvCount *uint64) {
	go func() {
		buffer := make([]byte, 8192)
		n, err := conn.Read(buffer)
		if err != nil {
			errChan <- err
			return
		}

		outChan <- string(buffer[:n])
		atomic.AddUint64(messageRecvCount, 1)
	}()

	for {
		if atomic.LoadUint64(messageRecvCount) == 2 {
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

func pickPort(t testing.TB) int {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to pickPort: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()
	switch addr := conn.LocalAddr().(type) {
	case *net.UDPAddr:
		return addr.Port
	default:
		t.Fatalf("unknown addr type %T", addr)
		return 0
	}
}

/*
  Simple DTLS Client/Server can communicate
    - Assert that you can send messages both ways
	- Assert that Close() on both ends work
	- Assert that no Goroutines are leaked
*/
func TestPionE2ESimple(t *testing.T) {
	expectedGoRoutineCount := runtime.NumGoroutine()

	serverPort := pickPort(t)

	for _, cipherSuite := range []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	} {
		errChan := make(chan error)
		clientChan := make(chan string)
		serverChan := make(chan string)
		var messageRecvCount uint64 // Counter to make sure both sides got a message

		serverPort++

		cert, key, err := dtls.GenerateSelfSigned()
		if err != nil {
			t.Fatal(err)
		}

		// DTLS Client
		go func() {
			conn, err := dtls.Dial("udp",
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
				&dtls.Config{Certificate: cert, PrivateKey: key, CipherSuites: []dtls.CipherSuiteID{cipherSuite}},
			)
			if err != nil {
				errChan <- err
				return
			}
			simpleReadWrite(errChan, clientChan, conn, nil, &messageRecvCount)
		}()

		// DTLS Server
		go func() {
			listener, err := dtls.Listen("udp",
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
				&dtls.Config{Certificate: cert, PrivateKey: key, CipherSuites: []dtls.CipherSuiteID{cipherSuite}},
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

			simpleReadWrite(errChan, serverChan, conn, listener, &messageRecvCount)
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

}
