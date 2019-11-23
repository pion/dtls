package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/transport/test"
)

const testMessage = "Hello World"
const testTimeLimit = 5 * time.Second
const messageRetry = 200 * time.Millisecond

func randomPort(t testing.TB) int {
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

func simpleReadWrite(errChan chan error, outChan chan string, conn io.ReadWriter, messageRecvCount *uint64) {
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
}

func assertE2ECommunication(clientConfig, serverConfig *dtls.Config, serverPort int, t *testing.T) {
	var (
		messageRecvCount uint64 // Counter to make sure both sides got a message
		clientMutex      sync.Mutex
		clientConn       net.Conn
		serverMutex      sync.Mutex
		serverConn       net.Conn
		serverListener   *dtls.Listener
		serverReady      = make(chan struct{})
		errChan          = make(chan error)
		clientChan       = make(chan string)
		serverChan       = make(chan string)
	)

	// DTLS Client
	go func() {
		select {
		case <-serverReady:
			// OK
		case <-time.After(time.Second):
			errChan <- errors.New("waiting on serverReady err: timeout")
		}

		clientMutex.Lock()
		defer clientMutex.Unlock()

		var err error
		clientConn, err = dtls.Dial("udp",
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
			clientConfig,
		)
		if err != nil {
			errChan <- err
			return
		}

		simpleReadWrite(errChan, clientChan, clientConn, &messageRecvCount)
	}()

	// DTLS Server
	go func() {
		serverMutex.Lock()
		defer serverMutex.Unlock()

		var err error
		serverListener, err = dtls.Listen("udp",
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
			serverConfig,
		)
		if err != nil {
			errChan <- err
			return
		}
		serverReady <- struct{}{}
		serverConn, err = serverListener.Accept()
		if err != nil {
			errChan <- err
			return
		}

		simpleReadWrite(errChan, serverChan, serverConn, &messageRecvCount)
	}()

	defer func() {
		clientMutex.Lock()
		serverMutex.Lock()
		defer clientMutex.Unlock()
		defer serverMutex.Unlock()

		if err := clientConn.Close(); err != nil {
			t.Fatal(err)
		}

		if err := serverConn.Close(); err != nil {
			t.Fatal(err)
		}

		if err := serverListener.Close(2 * time.Second); err != nil {
			t.Fatal(err)
		}
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
}

/*
  Simple DTLS Client/Server can communicate
    - Assert that you can send messages both ways
	- Assert that Close() on both ends work
	- Assert that no Goroutines are leaked
*/
func TestPionE2ESimple(t *testing.T) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	serverPort := randomPort(t)

	for _, cipherSuite := range []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	} {
		cert, key, err := dtls.GenerateSelfSigned()
		if err != nil {
			t.Fatal(err)
		}

		cfg := &dtls.Config{
			Certificate:        cert,
			PrivateKey:         key,
			CipherSuites:       []dtls.CipherSuiteID{cipherSuite},
			InsecureSkipVerify: true,
			ConnectTimeout:     dtls.ConnectTimeoutOption(2 * time.Second),
		}
		assertE2ECommunication(cfg, cfg, serverPort, t)

	}
}

func TestPionE2ESimpleED25519(t *testing.T) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	serverPort := randomPort(t)

	for _, cipherSuite := range []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	} {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := dtls.SelfSign(key)
		if err != nil {
			t.Fatal(err)
		}

		cfg := &dtls.Config{
			Certificate:        cert,
			PrivateKey:         key,
			CipherSuites:       []dtls.CipherSuiteID{cipherSuite},
			InsecureSkipVerify: true,
			ConnectTimeout:     dtls.ConnectTimeoutOption(5 * time.Second),
		}
		assertE2ECommunication(cfg, cfg, serverPort, t)
	}
}

func TestPionE2ESimplePSK(t *testing.T) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	serverPort := randomPort(t)

	for _, cipherSuite := range []dtls.CipherSuiteID{
		dtls.TLS_PSK_WITH_AES_128_CCM_8,
		dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
	} {
		cfg := &dtls.Config{
			PSK: func(hint []byte) ([]byte, error) {
				return []byte{0xAB, 0xC1, 0x23}, nil
			},
			PSKIdentityHint: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			CipherSuites:    []dtls.CipherSuiteID{cipherSuite},
			ConnectTimeout:  dtls.ConnectTimeoutOption(2 * time.Second),
		}
		assertE2ECommunication(cfg, cfg, serverPort, t)
	}
}

func TestPionE2EMTUs(t *testing.T) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	serverPort := randomPort(t)

	for _, mtu := range []int{
		10000,
		1000,
		100,
	} {
		cert, key, err := dtls.GenerateSelfSigned()
		if err != nil {
			t.Fatal(err)
		}

		cfg := &dtls.Config{
			Certificate:        cert,
			PrivateKey:         key,
			CipherSuites:       []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			InsecureSkipVerify: true,
			MTU:                mtu,
		}
		assertE2ECommunication(cfg, cfg, serverPort, t)
	}
}
