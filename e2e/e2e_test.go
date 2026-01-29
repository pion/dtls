// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
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

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
)

const (
	testMessage   = "Hello World"
	testTimeLimit = 5 * time.Second
	messageRetry  = 200 * time.Millisecond
)

var (
	errServerTimeout     = errors.New("waiting on serverReady err: timeout")
	errHookCiphersFailed = errors.New("hook failed to modify cipherlist")
	errHookAPLNFailed    = errors.New("hook failed to modify APLN extension")
)

func randomPort(tb testing.TB) int {
	tb.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0") // nolint: noctx
	assert.NoError(tb, err, "failed to pick port")

	defer func() {
		_ = conn.Close()
	}()
	switch addr := conn.LocalAddr().(type) {
	case *net.UDPAddr:
		return addr.Port
	default:
		assert.Fail(tb, "failed to acquire port", "unknown addr type %T", addr)

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
	ctx        context.Context //nolint:containedctx
	clientOpts []dtls.ClientOption
	serverOpts []dtls.ServerOption
	// OpenSSL test helpers need this information
	clientCipherSuites       []dtls.CipherSuiteID
	serverCipherSuites       []dtls.CipherSuiteID
	clientCertificates       []tls.Certificate
	serverCertificates       []tls.Certificate
	clientPSK                dtls.PSKCallback
	serverPSK                dtls.PSKCallback
	clientPSKIdentityHint    []byte
	serverPSKIdentityHint    []byte
	clientInsecureSkipVerify bool
	serverPort               int
	messageRecvCount         *uint64 // Counter to make sure both sides got a message
	clientMutex              *sync.Mutex
	clientConn               net.Conn
	clientDone               chan error
	serverMutex              *sync.Mutex
	serverConn               net.Conn
	serverListener           net.Listener
	serverReady              chan struct{}
	serverDone               chan error
	errChan                  chan error
	clientChan               chan string
	serverChan               chan string
	client                   func(*comm)
	server                   func(*comm)
}

func newComm(
	ctx context.Context,
	clientOpts []dtls.ClientOption,
	serverOpts []dtls.ServerOption,
	serverPort int,
	server, client func(*comm),
) *comm {
	messageRecvCount := uint64(0)

	com := &comm{
		ctx:              ctx,
		clientOpts:       clientOpts,
		serverOpts:       serverOpts,
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

	return com
}

// setOpenSSLInfo sets OpenSSL-specific information in the comm struct.
// This is called by test functions that have this information available.
func (c *comm) setOpenSSLInfo(
	clientCipherSuites []dtls.CipherSuiteID,
	serverCipherSuites []dtls.CipherSuiteID,
	clientCertificates []tls.Certificate,
	serverCertificates []tls.Certificate,
	clientPSK dtls.PSKCallback,
	serverPSK dtls.PSKCallback,
	clientPSKIdentityHint []byte,
	serverPSKIdentityHint []byte,
	clientInsecureSkipVerify bool,
) {
	c.clientCipherSuites = clientCipherSuites
	c.serverCipherSuites = serverCipherSuites
	c.clientCertificates = clientCertificates
	c.serverCertificates = serverCertificates
	c.clientPSK = clientPSK
	c.serverPSK = serverPSK
	c.clientPSKIdentityHint = clientPSKIdentityHint
	c.serverPSKIdentityHint = serverPSKIdentityHint
	c.clientInsecureSkipVerify = clientInsecureSkipVerify
}

func (c *comm) assert(t *testing.T) { //nolint:cyclop
	t.Helper()

	// DTLS Client
	go c.client(c)

	// DTLS Server
	go c.server(c)

	defer func() {
		if c.clientConn != nil {
			assert.NoError(t, c.clientConn.Close())
		}
		if c.serverConn != nil {
			assert.NoError(t, c.serverConn.Close())
		}
		if c.serverListener != nil {
			assert.NoError(t, c.serverListener.Close())
		}
	}()

	func() {
		seenClient, seenServer := false, false
		for {
			select {
			case err := <-c.errChan:
				assert.NoError(t, err)
			case <-time.After(testTimeLimit):
				assert.Failf(t, "Test timeout", "seenClient %t seenServer %t", seenClient, seenServer)
			case clientMsg := <-c.clientChan:
				assert.Equal(t, testMessage, clientMsg)

				seenClient = true
				if seenClient && seenServer {
					return
				}
			case serverMsg := <-c.serverChan:
				assert.Equal(t, testMessage, serverMsg)

				seenServer = true
				if seenClient && seenServer {
					return
				}
			}
		}
	}()
}

func (c *comm) cleanup(t *testing.T) {
	t.Helper()

	clientDone, serverDone := false, false
	for {
		select {
		case err := <-c.clientDone:
			assert.NoError(t, err)
			clientDone = true
			if clientDone && serverDone {
				return
			}
		case err := <-c.serverDone:
			assert.NoError(t, err)
			serverDone = true
			if clientDone && serverDone {
				return
			}
		case <-time.After(testTimeLimit):
			assert.Fail(t, "Test timeout waiting for server shutdown")
		}
	}
}

func clientPion(c *comm) { //nolint:varnamelen
	select {
	case <-c.serverReady:
		// OK
	case <-time.After(time.Second):
		c.errChan <- errServerTimeout
	}

	c.clientMutex.Lock()
	defer c.clientMutex.Unlock()

	conn, err := dtls.DialWithOptions("udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: c.serverPort},
		c.clientOpts...,
	)
	if err != nil {
		c.errChan <- err

		return
	}

	if err := conn.HandshakeContext(c.ctx); err != nil {
		c.errChan <- err

		return
	}

	c.clientConn = conn

	simpleReadWrite(c.errChan, c.clientChan, c.clientConn, c.messageRecvCount)
	c.clientDone <- nil
	close(c.clientDone)
}

func serverPion(c *comm) { //nolint:varnamelen
	c.serverMutex.Lock()
	defer c.serverMutex.Unlock()

	var err error
	c.serverListener, err = dtls.ListenWithOptions("udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: c.serverPort},
		c.serverOpts...,
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

	dtlsConn, ok := c.serverConn.(*dtls.Conn)
	if ok {
		if err := dtlsConn.HandshakeContext(c.ctx); err != nil {
			c.errChan <- err

			return
		}
	}

	simpleReadWrite(c.errChan, c.serverChan, c.serverConn, c.messageRecvCount)
	c.serverDone <- nil
	close(c.serverDone)
}

type dtlsTestOpts struct {
	clientOpts []dtls.ClientOption
	serverOpts []dtls.ServerOption
}

func withConnectionIDGenerator(g func() []byte) dtlsTestOpts {
	return dtlsTestOpts{
		clientOpts: []dtls.ClientOption{dtls.WithConnectionIDGenerator(g)},
		serverOpts: []dtls.ServerOption{dtls.WithConnectionIDGenerator(g)},
	}
}

// Simple DTLS Client/Server can communicate
//   - Assert that you can send messages both ways
//   - Assert that Close() on both ends work
//   - Assert that no Goroutines are leaked
func testPionE2ESimple(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
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
			assert.NoError(t, err)

			clientOpts := []dtls.ClientOption{
				dtls.WithCertificates(cert),
				dtls.WithCipherSuites(cipherSuite),
				dtls.WithInsecureSkipVerify(true),
			}
			serverOpts := []dtls.ServerOption{
				dtls.WithCertificates(cert),
				dtls.WithCipherSuites(cipherSuite),
				dtls.WithInsecureSkipVerify(true),
			}
			for _, o := range opts {
				clientOpts = append(clientOpts, o.clientOpts...)
				serverOpts = append(serverOpts, o.serverOpts...)
			}
			serverPort := randomPort(t)
			comm := newComm(ctx, clientOpts, serverOpts, serverPort, server, client)
			comm.setOpenSSLInfo(
				[]dtls.CipherSuiteID{cipherSuite}, []dtls.CipherSuiteID{cipherSuite},
				[]tls.Certificate{cert}, []tls.Certificate{cert},
				nil, nil, nil, nil, true)
			defer comm.cleanup(t)
			comm.assert(t)
		})
	}
}

func testPionE2ESimplePSK(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()

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

			clientOpts := []dtls.ClientOption{
				dtls.WithPSK(func([]byte) ([]byte, error) {
					return []byte{0xAB, 0xC1, 0x23}, nil
				}),
				dtls.WithPSKIdentityHint([]byte{0x01, 0x02, 0x03, 0x04, 0x05}),
				dtls.WithCipherSuites(cipherSuite),
			}
			serverOpts := []dtls.ServerOption{
				dtls.WithPSK(func([]byte) ([]byte, error) {
					return []byte{0xAB, 0xC1, 0x23}, nil
				}),
				dtls.WithPSKIdentityHint([]byte{0x01, 0x02, 0x03, 0x04, 0x05}),
				dtls.WithCipherSuites(cipherSuite),
			}
			for _, o := range opts {
				clientOpts = append(clientOpts, o.clientOpts...)
				serverOpts = append(serverOpts, o.serverOpts...)
			}
			serverPort := randomPort(t)
			comm := newComm(ctx, clientOpts, serverOpts, serverPort, server, client)
			pskFunc := func([]byte) ([]byte, error) {
				return []byte{0xAB, 0xC1, 0x23}, nil
			}
			pskHint := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
			comm.setOpenSSLInfo(
				[]dtls.CipherSuiteID{cipherSuite}, []dtls.CipherSuiteID{cipherSuite},
				nil, nil,
				pskFunc, pskFunc, pskHint, pskHint, false)
			defer comm.cleanup(t)
			comm.assert(t)
		})
	}
}

func testPionE2EMTUs(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	cipherSuite := dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

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
			assert.NoError(t, err)

			clientOpts := []dtls.ClientOption{
				dtls.WithCertificates(cert),
				dtls.WithCipherSuites(cipherSuite),
				dtls.WithInsecureSkipVerify(true),
				dtls.WithMTU(mtu),
			}
			serverOpts := []dtls.ServerOption{
				dtls.WithCertificates(cert),
				dtls.WithCipherSuites(cipherSuite),
				dtls.WithInsecureSkipVerify(true),
				dtls.WithMTU(mtu),
			}
			for _, o := range opts {
				clientOpts = append(clientOpts, o.clientOpts...)
				serverOpts = append(serverOpts, o.serverOpts...)
			}
			serverPort := randomPort(t)
			comm := newComm(ctx, clientOpts, serverOpts, serverPort, server, client)
			comm.setOpenSSLInfo(
				[]dtls.CipherSuiteID{cipherSuite},
				[]dtls.CipherSuiteID{cipherSuite},
				[]tls.Certificate{cert}, []tls.Certificate{cert},
				nil, nil, nil, nil, true)
			defer comm.cleanup(t)
			comm.assert(t)
		})
	}
}

func testPionE2ESimpleED25519(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()

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
			assert.NoError(t, err)
			cert, err := selfsign.SelfSign(key)
			assert.NoError(t, err)

			clientOpts := []dtls.ClientOption{
				dtls.WithCertificates(cert),
				dtls.WithCipherSuites(cipherSuite),
				dtls.WithInsecureSkipVerify(true),
			}
			serverOpts := []dtls.ServerOption{
				dtls.WithCertificates(cert),
				dtls.WithCipherSuites(cipherSuite),
				dtls.WithInsecureSkipVerify(true),
			}
			for _, o := range opts {
				clientOpts = append(clientOpts, o.clientOpts...)
				serverOpts = append(serverOpts, o.serverOpts...)
			}
			serverPort := randomPort(t)
			comm := newComm(ctx, clientOpts, serverOpts, serverPort, server, client)
			comm.setOpenSSLInfo(
				[]dtls.CipherSuiteID{cipherSuite},
				[]dtls.CipherSuiteID{cipherSuite},
				[]tls.Certificate{cert}, []tls.Certificate{cert},
				nil, nil, nil, nil, true)
			defer comm.cleanup(t)
			comm.assert(t)
		})
	}
}

func testPionE2ESimpleED25519ClientCert(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, skey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	scert, err := selfsign.SelfSign(skey)
	assert.NoError(t, err)

	_, ckey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	ccert, err := selfsign.SelfSign(ckey)
	assert.NoError(t, err)

	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(ccert),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithInsecureSkipVerify(true),
	}
	serverOpts := []dtls.ServerOption{
		dtls.WithCertificates(scert),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithClientAuth(dtls.RequireAnyClientCert),
	}
	for _, o := range opts {
		clientOpts = append(clientOpts, o.clientOpts...)
		serverOpts = append(serverOpts, o.serverOpts...)
	}
	serverPort := randomPort(t)
	comm := newComm(ctx, clientOpts, serverOpts, serverPort, server, client)
	comm.setOpenSSLInfo(
		[]dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		[]dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		[]tls.Certificate{ccert}, []tls.Certificate{scert},
		nil, nil, nil, nil, true)
	defer comm.cleanup(t)
	comm.assert(t)
}

func testPionE2ESimpleECDSAClientCert(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	ccert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	clientCAs := x509.NewCertPool()
	caCert, err := x509.ParseCertificate(ccert.Certificate[0])
	assert.NoError(t, err)
	clientCAs.AddCert(caCert)

	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(ccert),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithInsecureSkipVerify(true),
	}
	serverOpts := []dtls.ServerOption{
		dtls.WithClientCAs(clientCAs),
		dtls.WithCertificates(scert),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithClientAuth(dtls.RequireAnyClientCert),
	}
	for _, o := range opts {
		clientOpts = append(clientOpts, o.clientOpts...)
		serverOpts = append(serverOpts, o.serverOpts...)
	}
	serverPort := randomPort(t)
	comm := newComm(ctx, clientOpts, serverOpts, serverPort, server, client)
	comm.setOpenSSLInfo(
		[]dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		[]dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		[]tls.Certificate{ccert}, []tls.Certificate{scert},
		nil, nil, nil, nil, true)
	defer comm.cleanup(t)
	comm.assert(t)
}

func testPionE2ESimpleRSAClientCert(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	spriv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	scert, err := selfsign.SelfSign(spriv)
	assert.NoError(t, err)

	cpriv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	ccert, err := selfsign.SelfSign(cpriv)
	assert.NoError(t, err)

	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(ccert),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
		dtls.WithInsecureSkipVerify(true),
	}
	serverOpts := []dtls.ServerOption{
		dtls.WithCertificates(scert),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
		dtls.WithClientAuth(dtls.RequireAnyClientCert),
	}
	for _, o := range opts {
		clientOpts = append(clientOpts, o.clientOpts...)
		serverOpts = append(serverOpts, o.serverOpts...)
	}
	serverPort := randomPort(t)
	comm := newComm(ctx, clientOpts, serverOpts, serverPort, server, client)
	comm.setOpenSSLInfo(
		[]dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		[]dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		[]tls.Certificate{ccert}, []tls.Certificate{scert},
		nil, nil, nil, nil, true)
	defer comm.cleanup(t)
	comm.assert(t)
}

func testPionE2ESimpleClientHelloHook(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	t.Run("ClientHello hook", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		cert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
		assert.NoError(t, err)

		modifiedCipher := dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
		supportedList := []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
			modifiedCipher,
		}

		clientOpts := []dtls.ClientOption{
			dtls.WithCertificates(cert),
			dtls.WithVerifyConnection(func(s *dtls.State) error {
				if s.CipherSuiteID != modifiedCipher {
					return errHookCiphersFailed
				}

				return nil
			}),
			dtls.WithCipherSuites(supportedList...),
			dtls.WithClientHelloMessageHook(func(ch handshake.MessageClientHello) handshake.Message {
				ch.CipherSuiteIDs = []uint16{uint16(modifiedCipher)}

				return &ch
			}),
			dtls.WithInsecureSkipVerify(true),
		}

		serverOpts := []dtls.ServerOption{
			dtls.WithCertificates(cert),
			dtls.WithCipherSuites(supportedList...),
			dtls.WithInsecureSkipVerify(true),
		}

		for _, o := range opts {
			clientOpts = append(clientOpts, o.clientOpts...)
			serverOpts = append(serverOpts, o.serverOpts...)
		}
		serverPort := randomPort(t)
		comm := newComm(ctx, clientOpts, serverOpts, serverPort, server, client)
		comm.setOpenSSLInfo(
			supportedList, supportedList,
			[]tls.Certificate{cert}, []tls.Certificate{cert},
			nil, nil, nil, nil, true)
		defer comm.cleanup(t)
		comm.assert(t)
	})
}

func testPionE2ESimpleServerHelloHook(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	t.Run("ServerHello hook", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		cert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
		assert.NoError(t, err)

		supportedList := []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM}

		apln := "APLN"

		clientOpts := []dtls.ClientOption{
			dtls.WithCertificates(cert),
			dtls.WithVerifyConnection(func(s *dtls.State) error {
				if s.NegotiatedProtocol != apln {
					return errHookAPLNFailed
				}

				return nil
			}),
			dtls.WithCipherSuites(supportedList...),
			dtls.WithInsecureSkipVerify(true),
		}

		serverOpts := []dtls.ServerOption{
			dtls.WithCertificates(cert),
			dtls.WithCipherSuites(supportedList...),
			dtls.WithServerHelloMessageHook(func(sh handshake.MessageServerHello) handshake.Message {
				sh.Extensions = append(sh.Extensions, &extension.ALPN{
					ProtocolNameList: []string{apln},
				})

				return &sh
			}),
			dtls.WithInsecureSkipVerify(true),
		}

		for _, o := range opts {
			clientOpts = append(clientOpts, o.clientOpts...)
			serverOpts = append(serverOpts, o.serverOpts...)
		}
		serverPort := randomPort(t)
		comm := newComm(ctx, clientOpts, serverOpts, serverPort, server, client)
		comm.setOpenSSLInfo(
			supportedList, supportedList,
			[]tls.Certificate{cert}, []tls.Certificate{cert},
			nil, nil, nil, nil, true)
		defer comm.cleanup(t)
		comm.assert(t)
	})
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

func TestPionE2ESimpleClientHelloHook(t *testing.T) {
	testPionE2ESimpleClientHelloHook(t, serverPion, clientPion)
}

func TestPionE2ESimpleServerHelloHook(t *testing.T) {
	testPionE2ESimpleServerHelloHook(t, serverPion, clientPion)
}
