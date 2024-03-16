// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/pion/transport/v3/test"
)

const (
	testMessage   = "Hello World"
	testTimeLimit = 5 * time.Second
	messageRetry  = 200 * time.Millisecond
)

var errServerTimeout = errors.New("waiting on serverReady err: timeout")

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

type comm struct {
	ctx                        context.Context
	clientConfig, serverConfig *dtls.Config
	serverPort                 int
	messageRecvCount           *uint64 // Counter to make sure both sides got a message
	clientMutex                *sync.Mutex
	clientConn                 net.Conn
	clientDone                 chan error
	serverMutex                *sync.Mutex
	serverConn                 net.Conn
	serverListener             net.Listener
	serverReady                chan struct{}
	serverDone                 chan error
	errChan                    chan error
	clientChan                 chan string
	serverChan                 chan string
	client                     func(*comm)
	server                     func(*comm)
}

func newComm(ctx context.Context, clientConfig, serverConfig *dtls.Config, serverPort int, server, client func(*comm)) *comm {
	messageRecvCount := uint64(0)
	c := &comm{
		ctx:              ctx,
		clientConfig:     clientConfig,
		serverConfig:     serverConfig,
		serverPort:       serverPort,
		messageRecvCount: &messageRecvCount,
		clientMutex:      &sync.Mutex{},
		serverMutex:      &sync.Mutex{},
		serverReady:      make(chan struct{}),
		serverDone:       make(chan error),
		clientDone:       make(chan error),
		errChan:          make(chan error),
		clientChan:       make(chan string),
		serverChan:       make(chan string),
		server:           server,
		client:           client,
	}
	return c
}

func (c *comm) assert(t *testing.T) {
	// DTLS Client
	go c.client(c)

	// DTLS Server
	go c.server(c)

	defer func() {
		if c.clientConn != nil {
			if err := c.clientConn.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if c.serverConn != nil {
			if err := c.serverConn.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if c.serverListener != nil {
			if err := c.serverListener.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}()

	func() {
		seenClient, seenServer := false, false
		for {
			select {
			case err := <-c.errChan:
				t.Fatal(err)
			case <-time.After(testTimeLimit):
				t.Fatalf("Test timeout, seenClient %t seenServer %t", seenClient, seenServer)
			case clientMsg := <-c.clientChan:
				if clientMsg != testMessage {
					t.Fatalf("clientMsg does not equal test message: %s %s", clientMsg, testMessage)
				}

				seenClient = true
				if seenClient && seenServer {
					return
				}
			case serverMsg := <-c.serverChan:
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

func (c *comm) cleanup(t *testing.T) {
	clientDone, serverDone := false, false
	for {
		select {
		case err := <-c.clientDone:
			if err != nil {
				t.Fatal(err)
			}
			clientDone = true
			if clientDone && serverDone {
				return
			}
		case err := <-c.serverDone:
			if err != nil {
				t.Fatal(err)
			}
			serverDone = true
			if clientDone && serverDone {
				return
			}
		case <-time.After(testTimeLimit):
			t.Fatalf("Test timeout waiting for server shutdown")
		}
	}
}

func clientPion(c *comm) {
	select {
	case <-c.serverReady:
		// OK
	case <-time.After(time.Second):
		c.errChan <- errServerTimeout
	}

	c.clientMutex.Lock()
	defer c.clientMutex.Unlock()

	var err error
	c.clientConn, err = dtls.DialWithContext(c.ctx, "udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: c.serverPort},
		c.clientConfig,
	)
	if err != nil {
		c.errChan <- err
		return
	}

	simpleReadWrite(c.errChan, c.clientChan, c.clientConn, c.messageRecvCount)
	c.clientDone <- nil
	close(c.clientDone)
}

func serverPion(c *comm) {
	c.serverMutex.Lock()
	defer c.serverMutex.Unlock()

	var err error
	c.serverListener, err = dtls.Listen("udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: c.serverPort},
		c.serverConfig,
	)
	if err != nil {
		c.errChan <- err
		return
	}
	c.serverReady <- struct{}{}
	c.serverConn, err = c.serverListener.Accept()
	if err != nil {
		c.errChan <- err
		return
	}

	simpleReadWrite(c.errChan, c.serverChan, c.serverConn, c.messageRecvCount)
	c.serverDone <- nil
	close(c.serverDone)
}

type dtlsConfOpts func(*dtls.Config)

func withConnectionIDGenerator(g func() []byte) dtlsConfOpts {
	return func(c *dtls.Config) {
		c.ConnectionIDGenerator = g
	}
}

/*
	  Simple DTLS Client/Server can communicate
	    - Assert that you can send messages both ways
		- Assert that Close() on both ends work
		- Assert that no Goroutines are leaked
*/
func testPionE2ESimple(t *testing.T, server, client func(*comm), opts ...dtlsConfOpts) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	for _, cipherSuite := range []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	} {
		cipherSuite := cipherSuite
		t.Run(cipherSuite.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			cert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
			if err != nil {
				t.Fatal(err)
			}

			cfg := &dtls.Config{
				Certificates:       []tls.Certificate{cert},
				CipherSuites:       []dtls.CipherSuiteID{cipherSuite},
				InsecureSkipVerify: true,
			}
			for _, o := range opts {
				o(cfg)
			}
			serverPort := randomPort(t)
			comm := newComm(ctx, cfg, cfg, serverPort, server, client)
			defer comm.cleanup(t)
			comm.assert(t)
		})
	}
}

func testPionE2ESimplePSK(t *testing.T, server, client func(*comm), opts ...dtlsConfOpts) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	for _, cipherSuite := range []dtls.CipherSuiteID{
		dtls.TLS_PSK_WITH_AES_128_CCM,
		dtls.TLS_PSK_WITH_AES_128_CCM_8,
		dtls.TLS_PSK_WITH_AES_256_CCM_8,
		dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	} {
		cipherSuite := cipherSuite
		t.Run(cipherSuite.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			cfg := &dtls.Config{
				PSK: func([]byte) ([]byte, error) {
					return []byte{0xAB, 0xC1, 0x23}, nil
				},
				PSKIdentityHint: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
				CipherSuites:    []dtls.CipherSuiteID{cipherSuite},
			}
			for _, o := range opts {
				o(cfg)
			}
			serverPort := randomPort(t)
			comm := newComm(ctx, cfg, cfg, serverPort, server, client)
			defer comm.cleanup(t)
			comm.assert(t)
		})
	}
}

func testPionE2EMTUs(t *testing.T, server, client func(*comm), opts ...dtlsConfOpts) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	for _, mtu := range []int{
		10000,
		1000,
		100,
	} {
		mtu := mtu
		t.Run(fmt.Sprintf("MTU%d", mtu), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			cert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
			if err != nil {
				t.Fatal(err)
			}

			cfg := &dtls.Config{
				Certificates:       []tls.Certificate{cert},
				CipherSuites:       []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				InsecureSkipVerify: true,
				MTU:                mtu,
			}
			for _, o := range opts {
				o(cfg)
			}
			serverPort := randomPort(t)
			comm := newComm(ctx, cfg, cfg, serverPort, server, client)
			defer comm.cleanup(t)
			comm.assert(t)
		})
	}
}

func testPionE2ESimpleED25519(t *testing.T, server, client func(*comm), opts ...dtlsConfOpts) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	for _, cipherSuite := range []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	} {
		cipherSuite := cipherSuite
		t.Run(cipherSuite.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := selfsign.SelfSign(key)
			if err != nil {
				t.Fatal(err)
			}

			cfg := &dtls.Config{
				Certificates:       []tls.Certificate{cert},
				CipherSuites:       []dtls.CipherSuiteID{cipherSuite},
				InsecureSkipVerify: true,
			}
			for _, o := range opts {
				o(cfg)
			}
			serverPort := randomPort(t)
			comm := newComm(ctx, cfg, cfg, serverPort, server, client)
			defer comm.cleanup(t)
			comm.assert(t)
		})
	}
}

func testPionE2ESimpleED25519ClientCert(t *testing.T, server, client func(*comm), opts ...dtlsConfOpts) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, skey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scert, err := selfsign.SelfSign(skey)
	if err != nil {
		t.Fatal(err)
	}

	_, ckey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ccert, err := selfsign.SelfSign(ckey)
	if err != nil {
		t.Fatal(err)
	}

	scfg := &dtls.Config{
		Certificates: []tls.Certificate{scert},
		CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ClientAuth:   dtls.RequireAnyClientCert,
	}
	ccfg := &dtls.Config{
		Certificates:       []tls.Certificate{ccert},
		CipherSuites:       []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		InsecureSkipVerify: true,
	}
	for _, o := range opts {
		o(scfg)
		o(ccfg)
	}
	serverPort := randomPort(t)
	comm := newComm(ctx, ccfg, scfg, serverPort, server, client)
	defer comm.cleanup(t)
	comm.assert(t)
}

func testPionE2ESimpleECDSAClientCert(t *testing.T, server, client func(*comm), opts ...dtlsConfOpts) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	ccert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	clientCAs := x509.NewCertPool()
	caCert, err := x509.ParseCertificate(ccert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	clientCAs.AddCert(caCert)

	scfg := &dtls.Config{
		ClientCAs:    clientCAs,
		Certificates: []tls.Certificate{scert},
		CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ClientAuth:   dtls.RequireAnyClientCert,
	}
	ccfg := &dtls.Config{
		Certificates:       []tls.Certificate{ccert},
		CipherSuites:       []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		InsecureSkipVerify: true,
	}
	for _, o := range opts {
		o(scfg)
		o(ccfg)
	}
	serverPort := randomPort(t)
	comm := newComm(ctx, ccfg, scfg, serverPort, server, client)
	defer comm.cleanup(t)
	comm.assert(t)
}

func testPionE2ESimpleRSAClientCert(t *testing.T, server, client func(*comm), opts ...dtlsConfOpts) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	spriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	scert, err := selfsign.SelfSign(spriv)
	if err != nil {
		t.Fatal(err)
	}

	cpriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ccert, err := selfsign.SelfSign(cpriv)
	if err != nil {
		t.Fatal(err)
	}

	scfg := &dtls.Config{
		Certificates: []tls.Certificate{scert},
		CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		ClientAuth:   dtls.RequireAnyClientCert,
	}
	ccfg := &dtls.Config{
		Certificates:       []tls.Certificate{ccert},
		CipherSuites:       []dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		InsecureSkipVerify: true,
	}
	for _, o := range opts {
		o(scfg)
		o(ccfg)
	}
	serverPort := randomPort(t)
	comm := newComm(ctx, ccfg, scfg, serverPort, server, client)
	defer comm.cleanup(t)
	comm.assert(t)
}

func TestPionE2ESimple(t *testing.T) {
	testPionE2ESimple(t, serverPion, clientPion)
}

func TestPionE2ESimplePSK(t *testing.T) {
	testPionE2ESimplePSK(t, serverPion, clientPion)
}

func TestPionE2EMTUs(t *testing.T) {
	testPionE2EMTUs(t, serverPion, clientPion)
}

func TestPionE2ESimpleED25519(t *testing.T) {
	testPionE2ESimpleED25519(t, serverPion, clientPion)
}

func TestPionE2ESimpleED25519ClientCert(t *testing.T) {
	testPionE2ESimpleED25519ClientCert(t, serverPion, clientPion)
}

func TestPionE2ESimpleECDSAClientCert(t *testing.T) {
	testPionE2ESimpleECDSAClientCert(t, serverPion, clientPion)
}

func TestPionE2ESimpleRSAClientCert(t *testing.T) {
	testPionE2ESimpleRSAClientCert(t, serverPion, clientPion)
}

func TestPionE2ESimpleCID(t *testing.T) {
	testPionE2ESimple(t, serverPion, clientPion, withConnectionIDGenerator(dtls.RandomCIDGenerator(8)))
}

func TestPionE2ESimplePSKCID(t *testing.T) {
	testPionE2ESimplePSK(t, serverPion, clientPion, withConnectionIDGenerator(dtls.RandomCIDGenerator(8)))
}

func TestPionE2EMTUsCID(t *testing.T) {
	testPionE2EMTUs(t, serverPion, clientPion, withConnectionIDGenerator(dtls.RandomCIDGenerator(8)))
}

func TestPionE2ESimpleED25519CID(t *testing.T) {
	testPionE2ESimpleED25519(t, serverPion, clientPion, withConnectionIDGenerator(dtls.RandomCIDGenerator(8)))
}

func TestPionE2ESimpleED25519ClientCertCID(t *testing.T) {
	testPionE2ESimpleED25519ClientCert(t, serverPion, clientPion, withConnectionIDGenerator(dtls.RandomCIDGenerator(8)))
}

func TestPionE2ESimpleECDSAClientCertCID(t *testing.T) {
	testPionE2ESimpleECDSAClientCert(t, serverPion, clientPion, withConnectionIDGenerator(dtls.RandomCIDGenerator(8)))
}

func TestPionE2ESimpleRSAClientCertCID(t *testing.T) {
	testPionE2ESimpleRSAClientCert(t, serverPion, clientPion, withConnectionIDGenerator(dtls.RandomCIDGenerator(8)))
}
