// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package e2e

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
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
	clientCipherSuites       []cryptosuite.ID
	serverCipherSuites       []cryptosuite.ID
	clientCertificates       []tls.Certificate
	serverCertificates       []tls.Certificate
	clientPSK                dtls.PSKCallback
	serverPSK                dtls.PSKCallback
	clientPSKIdentityHint    []byte
	serverPSKIdentityHint    []byte
	clientInsecureSkipVerify bool
	serverPort               int
	messageRecvCount         uint64 // Counter to make sure both sides got a message
	clientMutex              sync.Mutex
	clientConn               net.Conn
	clientDone               chan error
	serverMutex              sync.Mutex
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

	timer := time.NewTimer(testTimeLimit)
	defer timer.Stop()

	seenClient, seenServer := false, false
	for {
		select {
		case err := <-c.errChan:
			assert.NoError(t, err)

			return
		case <-timer.C:
			assert.Failf(t, "Test timeout", "seenClient %t seenServer %t", seenClient, seenServer)

			return
		case clientMsg := <-c.clientChan:
			if !assert.Equal(t, testMessage, clientMsg) {
				return
			}

			seenClient = true
			if seenClient && seenServer {
				return
			}
		case serverMsg := <-c.serverChan:
			if !assert.Equal(t, testMessage, serverMsg) {
				return
			}

			seenServer = true
			if seenClient && seenServer {
				return
			}
		}
	}
}

func (c *comm) cleanup(t *testing.T) {
	t.Helper()

	clientDone, serverDone := false, false
	clientDoneCh, serverDoneCh := c.clientDone, c.serverDone
	timer := time.NewTimer(testTimeLimit)
	defer timer.Stop()

	for {
		select {
		case err := <-clientDoneCh:
			assert.NoError(t, err)
			clientDone = true
			clientDoneCh = nil
			if clientDone && serverDone {
				return
			}
		case err := <-serverDoneCh:
			assert.NoError(t, err)
			serverDone = true
			serverDoneCh = nil
			if clientDone && serverDone {
				return
			}
		case <-timer.C:
			assert.Fail(t, "Test timeout waiting for server shutdown")

			return
		}
	}
}

func clientPion(c *comm) { //nolint:varnamelen
	var result error
	defer func() {
		c.clientDone <- result
		close(c.clientDone)
	}()

	select {
	case <-c.serverReady:
		// OK
	case <-time.After(time.Second):
		result = errServerTimeout
		c.errChan <- result

		return
	}

	c.clientMutex.Lock()
	defer c.clientMutex.Unlock()

	conn, err := dtls.Dial("udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: c.serverPort},
		c.clientOpts...,
	)
	if err != nil {
		result = err
		c.errChan <- result

		return
	}
	c.clientConn = conn

	if err := conn.HandshakeContext(c.ctx); err != nil {
		result = err
		c.errChan <- result

		return
	}

	simpleReadWrite(c.errChan, c.clientChan, c.clientConn, &c.messageRecvCount)
}

func serverPion(c *comm) { //nolint:varnamelen
	var result error
	defer func() {
		c.serverDone <- result
		close(c.serverDone)
	}()

	c.serverMutex.Lock()
	defer c.serverMutex.Unlock()

	var err error
	c.serverListener, err = dtls.ListenAddr("udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: c.serverPort},
		c.serverOpts...,
	)
	if err != nil {
		result = err
		c.errChan <- result

		return
	}
	c.serverReady <- struct{}{}
	c.serverConn, err = c.serverListener.Accept()
	if err != nil {
		result = err
		c.errChan <- result

		return
	}

	dtlsConn, ok := c.serverConn.(*dtls.Conn)
	if ok {
		if err := dtlsConn.HandshakeContext(c.ctx); err != nil {
			result = err
			c.errChan <- result

			return
		}
	}

	simpleReadWrite(c.errChan, c.serverChan, c.serverConn, &c.messageRecvCount)
}

type dtlsTestOpts struct {
	clientOpts []dtls.ClientOption
	serverOpts []dtls.ServerOption
}

type commOpts struct {
	timeout                  time.Duration
	clientOpts               []dtls.ClientOption
	serverOpts               []dtls.ServerOption
	clientCipherSuites       []cryptosuite.ID
	serverCipherSuites       []cryptosuite.ID
	clientCertificates       []tls.Certificate
	serverCertificates       []tls.Certificate
	clientPSK                dtls.PSKCallback
	serverPSK                dtls.PSKCallback
	clientPSKIdentityHint    []byte
	serverPSKIdentityHint    []byte
	clientInsecureSkipVerify bool
}

func guardTest(t *testing.T) {
	t.Helper()
	lim := test.TimeOut(30 * time.Second)
	t.Cleanup(func() { lim.Stop() })
	t.Cleanup(test.CheckRoutines(t))
}

func runComm(t *testing.T, server, client func(*comm), cfg commOpts, opts ...dtlsTestOpts) {
	t.Helper()
	if cfg.timeout == 0 {
		cfg.timeout = testTimeLimit
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	for _, opt := range opts {
		cfg.clientOpts = append(cfg.clientOpts, opt.clientOpts...)
		cfg.serverOpts = append(cfg.serverOpts, opt.serverOpts...)
	}
	c := &comm{
		ctx: ctx, clientOpts: cfg.clientOpts, serverOpts: cfg.serverOpts,
		serverPort: randomPort(t), server: server, client: client,
		serverReady: make(chan struct{}, 1), serverDone: make(chan error, 1), clientDone: make(chan error, 1),
		errChan: make(chan error, 4), clientChan: make(chan string, 1), serverChan: make(chan string, 1),
	}
	c.clientCipherSuites, c.serverCipherSuites = cfg.clientCipherSuites, cfg.serverCipherSuites
	c.clientCertificates, c.serverCertificates = cfg.clientCertificates, cfg.serverCertificates
	c.clientPSK, c.serverPSK = cfg.clientPSK, cfg.serverPSK
	c.clientPSKIdentityHint, c.serverPSKIdentityHint = cfg.clientPSKIdentityHint, cfg.serverPSKIdentityHint
	c.clientInsecureSkipVerify = cfg.clientInsecureSkipVerify
	defer c.cleanup(t)
	c.assert(t)
}

func withConnectionID(g func() []byte) dtlsTestOpts {
	return dtlsTestOpts{
		clientOpts: []dtls.ClientOption{dtls.WithConnectionID(g, dtls.CIDPathMigrationUnsafe)},
		serverOpts: []dtls.ServerOption{dtls.WithConnectionID(g, dtls.CIDPathMigrationUnsafe)},
	}
}

// Simple DTLS Client/Server can communicate
//   - Assert that you can send messages both ways
//   - Assert that Close() on both ends work
//   - Assert that no Goroutines are leaked
func testPionE2EWithCipherSuites(
	t *testing.T,
	server, client func(*comm),
	cipherSuites []cryptosuite.ID,
	makeCert func(*testing.T) tls.Certificate,
	opts ...dtlsTestOpts,
) {
	t.Helper()
	guardTest(t)

	for _, cipherSuite := range cipherSuites {
		t.Run(cipherSuite.String(), func(t *testing.T) {
			cert := makeCert(t)
			clientOpts := []dtls.ClientOption{dtls.WithCertificates(cert), dtls.WithCipherSuites(cipherSuite), dtls.WithInsecureSkipVerify(true)} //nolint:lll // Compact option matrix.
			serverOpts := []dtls.ServerOption{dtls.WithCertificates(cert), dtls.WithCipherSuites(cipherSuite), dtls.WithInsecureSkipVerify(true)} //nolint:lll // Compact option matrix.
			runComm(t, server, client, commOpts{
				clientOpts: clientOpts, serverOpts: serverOpts,
				clientCipherSuites: []cryptosuite.ID{cipherSuite}, serverCipherSuites: []cryptosuite.ID{cipherSuite},
				clientCertificates: []tls.Certificate{cert}, serverCertificates: []tls.Certificate{cert},
				clientInsecureSkipVerify: true,
			}, opts...)
		})
	}
}

func selfSignedECDSACert(t *testing.T) tls.Certificate {
	t.Helper()
	cert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
	assert.NoError(t, err)

	return cert
}

func selfSignedRSACert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	cert, err := selfsign.SelfSign(priv)
	assert.NoError(t, err)

	return cert
}

func testPionE2ESimple(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EWithCipherSuites(t, server, client, []cryptosuite.ID{
		cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	}, selfSignedECDSACert, opts...)
}

func testPionE2ESimpleRSA(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EWithCipherSuites(t, server, client, []cryptosuite.ID{
		cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		cryptosuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		cryptosuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	}, selfSignedRSACert, opts...)
}

func testPionE2EChaCha20Poly1305(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EWithCipherSuites(t, server, client, []cryptosuite.ID{
		cryptosuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}, selfSignedECDSACert, opts...)
}

func testPionE2EChaCha20Poly1305RSA(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EWithCipherSuites(t, server, client, []cryptosuite.ID{
		cryptosuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}, selfSignedRSACert, opts...)
}

func testPionE2EPSK(
	t *testing.T,
	server, client func(*comm),
	cipherSuites []cryptosuite.ID,
	pskHint []byte,
	hintOnServer bool,
	opts ...dtlsTestOpts,
) {
	t.Helper()
	guardTest(t)
	for _, cipherSuite := range cipherSuites {
		t.Run(cipherSuite.String(), func(t *testing.T) {
			pskFunc := func([]byte) ([]byte, error) {
				return []byte{0xAB, 0xC1, 0x23}, nil
			}
			clientOpts := []dtls.ClientOption{dtls.WithPSK(pskFunc), dtls.WithPSKIdentityHint(pskHint), dtls.WithCipherSuites(cipherSuite)} //nolint:lll // Compact option matrix.
			serverOpts := []dtls.ServerOption{dtls.WithPSK(pskFunc), dtls.WithCipherSuites(cipherSuite)}
			if hintOnServer {
				serverOpts = append(serverOpts, dtls.WithPSKIdentityHint(pskHint))
			}
			runComm(t, server, client, commOpts{
				clientOpts: clientOpts, serverOpts: serverOpts,
				clientCipherSuites: []cryptosuite.ID{cipherSuite}, serverCipherSuites: []cryptosuite.ID{cipherSuite},
				clientPSK: pskFunc, serverPSK: pskFunc,
				clientPSKIdentityHint: pskHint, serverPSKIdentityHint: pskHint,
			}, opts...)
		})
	}
}

func testPionE2ESimplePSK(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EPSK(t, server, client, []cryptosuite.ID{
		cryptosuite.TLS_PSK_WITH_AES_128_CCM,
		cryptosuite.TLS_PSK_WITH_AES_128_CCM_8,
		cryptosuite.TLS_PSK_WITH_AES_256_CCM_8,
		cryptosuite.TLS_PSK_WITH_AES_128_GCM_SHA256,
		cryptosuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	}, []byte{0x01, 0x02, 0x03, 0x04, 0x05}, true, opts...)
}

func testPionE2EChaCha20Poly1305PSK(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EPSK(t, server, client, []cryptosuite.ID{
		cryptosuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
	}, []byte{0x01, 0x02, 0x03}, false, opts...)
}

func testPionE2EMTUs(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	guardTest(t)
	cipherSuite := cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	for _, mtu := range []int{10000, 1000, 100} {
		t.Run(fmt.Sprintf("MTU%d", mtu), func(t *testing.T) {
			cert := selfSignedECDSACert(t)
			clientOpts := []dtls.ClientOption{dtls.WithCertificates(cert), dtls.WithCipherSuites(cipherSuite), dtls.WithInsecureSkipVerify(true), dtls.WithMTU(mtu)} //nolint:lll // Compact option matrix.
			serverOpts := []dtls.ServerOption{dtls.WithCertificates(cert), dtls.WithCipherSuites(cipherSuite), dtls.WithInsecureSkipVerify(true), dtls.WithMTU(mtu)} //nolint:lll // Compact option matrix.
			runComm(t, server, client, commOpts{
				timeout: 10 * time.Second, clientOpts: clientOpts, serverOpts: serverOpts,
				clientCipherSuites: []cryptosuite.ID{cipherSuite}, serverCipherSuites: []cryptosuite.ID{cipherSuite},
				clientCertificates: []tls.Certificate{cert}, serverCertificates: []tls.Certificate{cert},
				clientInsecureSkipVerify: true,
			}, opts...)
		})
	}
}

func testPionE2ESimpleED25519(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EWithCipherSuites(t, server, client, []cryptosuite.ID{
		cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	}, func(t *testing.T) tls.Certificate {
		t.Helper()
		_, key, err := ed25519.GenerateKey(rand.Reader)
		assert.NoError(t, err)
		cert, err := selfsign.SelfSign(key)
		assert.NoError(t, err)

		return cert
	}, opts...)
}

func testPionE2EClientCert(
	t *testing.T,
	server, client func(*comm),
	cipherSuite cryptosuite.ID,
	makeCert func(*testing.T) tls.Certificate,
	withClientCA bool,
	opts ...dtlsTestOpts,
) {
	t.Helper()
	guardTest(t)
	scert, ccert := makeCert(t), makeCert(t)

	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(ccert),
		dtls.WithCipherSuites(cipherSuite),
		dtls.WithInsecureSkipVerify(true),
	}
	serverOpts := []dtls.ServerOption{
		dtls.WithCertificates(scert),
		dtls.WithCipherSuites(cipherSuite),
		dtls.WithClientAuth(dtls.RequireAnyClientCert),
	}
	if withClientCA {
		clientCAs := x509.NewCertPool()
		caCert, err := x509.ParseCertificate(ccert.Certificate[0])
		assert.NoError(t, err)
		clientCAs.AddCert(caCert)
		serverOpts = append(serverOpts, dtls.WithClientCAs(clientCAs))
	}
	runComm(t, server, client, commOpts{
		clientOpts: clientOpts, serverOpts: serverOpts,
		clientCipherSuites: []cryptosuite.ID{cipherSuite}, serverCipherSuites: []cryptosuite.ID{cipherSuite},
		clientCertificates: []tls.Certificate{ccert}, serverCertificates: []tls.Certificate{scert},
		clientInsecureSkipVerify: true,
	}, opts...)
}

func testPionE2ESimpleED25519ClientCert(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EClientCert(t, server, client, cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, func(t *testing.T) tls.Certificate { //nolint:lll // Compact scenario wrapper.
		t.Helper()
		_, key, err := ed25519.GenerateKey(rand.Reader)
		assert.NoError(t, err)
		cert, err := selfsign.SelfSign(key)
		assert.NoError(t, err)

		return cert
	}, false, opts...)
}

func testPionE2ESimpleECDSAClientCert(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EClientCert(t, server, client, cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, selfSignedECDSACert, true, opts...) //nolint:lll // Compact scenario wrapper.
}

func testPionE2ESimpleRSAClientCert(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EClientCert(t, server, client, cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, selfSignedRSACert, false, opts...) //nolint:lll // Compact scenario wrapper.
}

func testPionE2ESimpleClientHelloHook(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	guardTest(t)

	t.Run("ClientHello hook", func(t *testing.T) {
		cert := selfSignedECDSACert(t)

		modifiedCipher := cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
		supportedList := []cryptosuite.ID{
			cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
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

		runComm(t, server, client, commOpts{
			clientOpts: clientOpts, serverOpts: serverOpts,
			clientCipherSuites: supportedList, serverCipherSuites: supportedList,
			clientCertificates: []tls.Certificate{cert}, serverCertificates: []tls.Certificate{cert},
			clientInsecureSkipVerify: true,
		}, opts...)
	})
}

func testPionE2ESimpleServerHelloHook(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	guardTest(t)

	t.Run("ServerHello hook", func(t *testing.T) {
		cert := selfSignedECDSACert(t)

		supportedList := []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM}

		apln := "APLN"

		clientOpts := []dtls.ClientOption{
			dtls.WithCertificates(cert),
			dtls.WithSupportedProtocols(apln),
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
				sh.Extensions = append(sh.Extensions, &extension.ALPNSelection{Protocol: apln})

				return &sh
			}),
			dtls.WithInsecureSkipVerify(true),
		}

		runComm(t, server, client, commOpts{
			clientOpts: clientOpts, serverOpts: serverOpts,
			clientCipherSuites: supportedList, serverCipherSuites: supportedList,
			clientCertificates: []tls.Certificate{cert}, serverCertificates: []tls.Certificate{cert},
			clientInsecureSkipVerify: true,
		}, opts...)
	})
}

type pionE2ETest func(*testing.T, func(*comm), func(*comm), ...dtlsTestOpts)

func TestPionE2E(t *testing.T) {
	tests := map[string]struct {
		run pionE2ETest
		cid bool
	}{
		"Simple":                     {run: testPionE2ESimple},
		"SimpleRSA":                  {run: testPionE2ESimpleRSA},
		"ChaCha20Poly1305":           {run: testPionE2EChaCha20Poly1305},
		"ChaCha20Poly1305RSA":        {run: testPionE2EChaCha20Poly1305RSA},
		"SimplePSK":                  {run: testPionE2ESimplePSK},
		"ChaCha20Poly1305PSK":        {run: testPionE2EChaCha20Poly1305PSK},
		"MTUs":                       {run: testPionE2EMTUs},
		"SimpleED25519":              {run: testPionE2ESimpleED25519},
		"SimpleED25519ClientCert":    {run: testPionE2ESimpleED25519ClientCert},
		"SimpleECDSAClientCert":      {run: testPionE2ESimpleECDSAClientCert},
		"SimpleRSAClientCert":        {run: testPionE2ESimpleRSAClientCert},
		"SimpleCID":                  {run: testPionE2ESimple, cid: true},
		"ChaCha20Poly1305CID":        {run: testPionE2EChaCha20Poly1305, cid: true},
		"ChaCha20Poly1305RSACID":     {run: testPionE2EChaCha20Poly1305RSA, cid: true},
		"SimplePSKCID":               {run: testPionE2ESimplePSK, cid: true},
		"ChaCha20Poly1305PSKCID":     {run: testPionE2EChaCha20Poly1305PSK, cid: true},
		"MTUsCID":                    {run: testPionE2EMTUs, cid: true},
		"SimpleED25519CID":           {run: testPionE2ESimpleED25519, cid: true},
		"SimpleED25519ClientCertCID": {run: testPionE2ESimpleED25519ClientCert, cid: true},
		"SimpleECDSAClientCertCID":   {run: testPionE2ESimpleECDSAClientCert, cid: true},
		"SimpleRSAClientCertCID":     {run: testPionE2ESimpleRSAClientCert, cid: true},
		"SimpleClientHelloHook":      {run: testPionE2ESimpleClientHelloHook},
		"SimpleServerHelloHook":      {run: testPionE2ESimpleServerHelloHook},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.cid {
				test.run(t, serverPion, clientPion, withConnectionID(dtls.RandomCIDGenerator(8)))

				return
			}
			test.run(t, serverPion, clientPion)
		})
	}
}

func testCertificateSignatureSchemes(
	t *testing.T,
	cert tls.Certificate,
	cipherSuite cryptosuite.ID,
	schemes ...tls.SignatureScheme,
) {
	t.Helper()
	guardTest(t)
	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(cert),
		dtls.WithCipherSuites(cipherSuite),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithCertificateSignatureSchemes(schemes...),
	}
	serverOpts := []dtls.ServerOption{
		dtls.WithCertificates(cert),
		dtls.WithCipherSuites(cipherSuite),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithCertificateSignatureSchemes(schemes...),
	}
	runComm(t, serverPion, clientPion, commOpts{
		clientOpts: clientOpts, serverOpts: serverOpts,
		clientCipherSuites: []cryptosuite.ID{cipherSuite}, serverCipherSuites: []cryptosuite.ID{cipherSuite},
		clientCertificates: []tls.Certificate{cert}, serverCertificates: []tls.Certificate{cert},
		clientInsecureSkipVerify: true,
	})
}

// TestCertificateSignatureSchemesAllowed tests that connections succeed when
// certificate chains use only allowed signature algorithms.
func TestCertificateSignatureSchemesAllowed(t *testing.T) {
	testCertificateSignatureSchemes(t, selfSignedECDSACert(t),
		cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512,
	)
}

// TestCertificateSignatureSchemesRSA tests RSA certificates with signature schemes.
func TestCertificateSignatureSchemesRSA(t *testing.T) {
	testCertificateSignatureSchemes(t, selfSignedRSACert(t),
		cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512,
		tls.PKCS1WithSHA256, tls.PKCS1WithSHA384, tls.PKCS1WithSHA512,
	)
}

// TestCertificateSignatureSchemesClientCert tests certificate signature validation
// with client certificates using different ECDSA curves.
func TestCertificateSignatureSchemesClientCert(t *testing.T) {
	guardTest(t)
	// Server uses P-256 ECDSA
	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	// Client uses P-384 ECDSA
	clientKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)
	clientCert, err := selfsign.SelfSign(clientKey)
	assert.NoError(t, err)

	clientCAs := x509.NewCertPool()
	caCert, err := x509.ParseCertificate(clientCert.Certificate[0])
	assert.NoError(t, err)
	clientCAs.AddCert(caCert)

	// Both sides accept P-256 and P-384 ECDSA
	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(clientCert),
		dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithCertificateSignatureSchemes(
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
		),
	}

	serverOpts := []dtls.ServerOption{
		dtls.WithClientCAs(clientCAs),
		dtls.WithCertificates(serverCert),
		dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithClientAuth(dtls.RequireAnyClientCert),
		dtls.WithCertificateSignatureSchemes(
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
		),
	}

	runComm(t, serverPion, clientPion, commOpts{
		clientOpts: clientOpts, serverOpts: serverOpts,
		clientCipherSuites: []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		serverCipherSuites: []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		clientCertificates: []tls.Certificate{clientCert}, serverCertificates: []tls.Certificate{serverCert},
		clientInsecureSkipVerify: true,
	})
}

// createCertChain creates a certificate chain with a root CA and a leaf certificate
// signed by the CA. The CA uses the same key type as the leaf to ensure consistent
// signature algorithms in the chain. This allows testing signature algorithm validation.
func generateKey(t *testing.T, keyType string) (crypto.Signer, crypto.PublicKey) {
	t.Helper()
	var key crypto.Signer
	var err error
	switch keyType {
	case "ecdsa-p256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		assert.FailNowf(t, "unknown key type", "unknown key type: %s", keyType)
	}
	assert.NoError(t, err)

	return key, key.Public()
}

func createCertChain(t *testing.T, leafKeyType string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	// Create root CA with matching key type
	caKey, caPubKey := generateKey(t, leafKeyType)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPubKey, caKey)
	assert.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	assert.NoError(t, err)

	// Create leaf certificate with same key type, signed by CA
	leafKey, leafPubKey := generateKey(t, leafKeyType)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	var leafCertDER []byte
	leafCertDER, err = x509.CreateCertificate(rand.Reader, leafTemplate, caCert, leafPubKey, caKey)
	assert.NoError(t, err)

	// Create tls.Certificate with full chain
	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafCertDER, caCertDER},
		PrivateKey:  leafKey,
	}

	// Create root CA pool
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCert)

	return tlsCert, rootCAs
}

// assertHandshakeFailsWithOpts runs a DTLS handshake that is expected to fail
// on both the client and server sides.
func assertHandshakeFailsWithOpts(
	t *testing.T,
	clientOpts []dtls.ClientOption,
	serverOpts []dtls.ServerOption,
	clientErrMsg string,
) {
	t.Helper()
	guardTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverPort := randomPort(t)

	serverReady := make(chan struct{})
	serverDone := make(chan error, 1)

	go func() {
		listener, listenerErr := dtls.ListenAddr("udp",
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
			serverOpts...,
		)
		if listenerErr != nil {
			serverDone <- listenerErr

			return
		}
		defer func() { _ = listener.Close() }()

		serverReady <- struct{}{}
		serverConn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr

			return
		}
		defer func() { _ = serverConn.Close() }()

		var handshakeErr error
		if dtlsConn, ok := serverConn.(*dtls.Conn); ok {
			handshakeErr = dtlsConn.HandshakeContext(ctx)
		}
		serverDone <- handshakeErr
	}()

	select {
	case <-serverReady:
	case <-time.After(time.Second):
		assert.FailNow(t, "server not ready in time")
	}

	conn, err := dtls.Dial("udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
		clientOpts...,
	)

	if err == nil && conn != nil {
		err = conn.HandshakeContext(ctx)
		_ = conn.Close()
	}

	assert.Error(t, err, clientErrMsg)

	select {
	case serverErr := <-serverDone:
		assert.Error(t, serverErr)
	case <-time.After(2 * time.Second):
		t.Log("server did not complete in time")
	}
}

func testServerCertRejected(
	t *testing.T,
	keyType string,
	cipherSuite cryptosuite.ID,
	schemes []tls.SignatureScheme,
	message string,
) {
	t.Helper()
	serverCert, serverRootCAs := createCertChain(t, keyType)
	clientCert := selfSignedECDSACert(t)
	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(clientCert),
		dtls.WithCipherSuites(cipherSuite),
		dtls.WithRootCAs(serverRootCAs),
		dtls.WithCertificateSignatureSchemes(schemes...),
	}
	serverOpts := []dtls.ServerOption{
		dtls.WithCertificates(serverCert),
		dtls.WithCipherSuites(cipherSuite),
		dtls.WithInsecureSkipVerify(true),
	}
	assertHandshakeFailsWithOpts(t, clientOpts, serverOpts, message)
}

// TestCertificateSignatureSchemesServerCertRejected tests that client rejects
// server certificate when it uses a disallowed signature algorithm.
func TestCertificateSignatureSchemesServerCertRejected(t *testing.T) {
	testServerCertRejected(t, "ecdsa-p256", cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		[]tls.SignatureScheme{tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512},
		"expected handshake to fail with disallowed signature scheme",
	)
}

// TestCertificateSignatureSchemesClientCertRejected tests that server rejects
// client certificate when it uses a disallowed signature algorithm.
func TestCertificateSignatureSchemesClientCertRejected(t *testing.T) {
	// Server uses self-signed cert (client won't validate)
	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	// Client uses P-256 ECDSA certificate chain
	clientCert, clientRootCAs := createCertChain(t, "ecdsa-p256")

	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(clientCert),
		dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithInsecureSkipVerify(true),
	}

	// Server only allows P-384 and P-521 for client cert, but client uses P-256
	serverOpts := []dtls.ServerOption{
		dtls.WithClientCAs(clientRootCAs),
		dtls.WithCertificates(serverCert),
		dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithClientAuth(dtls.RequireAndVerifyClientCert),
		dtls.WithCertificateSignatureSchemes(
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
		),
	}

	assertHandshakeFailsWithOpts(
		t, clientOpts, serverOpts,
		"expected handshake to fail with disallowed client cert signature scheme",
	)
}

// TestCertificateSignatureSchemesRSAMismatch tests that connections fail when
// RSA certificate is presented but only ECDSA schemes are allowed.
func TestCertificateSignatureSchemesRSAMismatch(t *testing.T) {
	testServerCertRejected(t, "rsa", cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		[]tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384},
		"expected handshake to fail with RSA cert but ECDSA-only schemes",
	)
}
