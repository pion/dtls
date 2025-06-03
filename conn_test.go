// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	cryptoElliptic "crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/pion/transport/v3/dpipe"
	"github.com/pion/transport/v3/test"
	"github.com/stretchr/testify/assert"
)

var (
	errTestPSKInvalidIdentity = errors.New("TestPSK: Server got invalid identity")
	errPSKRejected            = errors.New("PSK Rejected")
	errNotExpectedChain       = errors.New("not expected chain")
	errExpecedChain           = errors.New("expected chain")
	errWrongCert              = errors.New("wrong cert")
)

func TestStressDuplex(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	// Run the test
	stressDuplex(t)
}

func stressDuplex(t *testing.T) {
	t.Helper()

	ca, cb, err := pipeMemory()
	assert.NoError(t, err)

	defer func() {
		assert.NoError(t, ca.Close())
		assert.NoError(t, cb.Close())
	}()

	opt := test.Options{
		MsgSize:  2048,
		MsgCount: 100,
	}

	assert.NoError(t, test.StressDuplex(ca, cb, opt))
}

func TestRoutineLeakOnClose(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ca, cb, err := pipeMemory()
	assert.NoError(t, err)

	_, err = ca.Write(make([]byte, 100))
	assert.NoError(t, err)
	assert.NoError(t, cb.Close())
	assert.NoError(t, ca.Close())
	// Packet is sent, but not read.
	// inboundLoop routine should not be leaked.
}

func TestReadWriteDeadline(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	var netErr net.Error

	ca, cb, err := pipeMemory()
	assert.NoError(t, err)
	assert.NoError(t, ca.SetDeadline(time.Unix(0, 1)))

	_, werr := ca.Write(make([]byte, 100))
	assert.ErrorAs(t, werr, &netErr, "Write must return net.Error")
	assert.True(t, netErr.Timeout(), "Deadline exceeded Write must return Timeout")
	assert.True(t, netErr.Temporary(), "Deadline exceeded Write must return Temporary") //nolint:staticcheck

	_, rerr := ca.Read(make([]byte, 100))
	assert.ErrorAs(t, rerr, &netErr, "Read must return net.Error")
	assert.True(t, netErr.Timeout(), "Deadline exceeded Read must return Timeout")
	assert.True(t, netErr.Temporary(), "Deadline exceeded Read must return Temporary") //nolint:staticcheck
	assert.NoError(t, ca.SetDeadline(time.Time{}))
	assert.NoError(t, ca.Close())
	assert.NoError(t, cb.Close())

	_, err = ca.Write(make([]byte, 100))
	assert.ErrorIs(t, err, ErrConnClosed)
	_, err = ca.Read(make([]byte, 100))
	assert.ErrorIs(t, err, io.EOF)
}

func TestSequenceNumberOverflow(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	t.Run("ApplicationData", func(t *testing.T) {
		ca, cb, err := pipeMemory()
		assert.NoError(t, err)

		atomic.StoreUint64(&ca.state.localSequenceNumber[1], recordlayer.MaxSequenceNumber)
		_, werr := ca.Write(make([]byte, 100))
		assert.NoError(t, werr, "Write must send message with maximum sequence number")
		_, werr = ca.Write(make([]byte, 100))
		assert.ErrorIs(t, werr, errSequenceNumberOverflow, "Write must abandonsend message with maximum sequence number")

		assert.NoError(t, ca.Close())
		assert.NoError(t, cb.Close())
	})
	t.Run("Handshake", func(t *testing.T) {
		ca, cb, err := pipeMemory()
		assert.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		atomic.StoreUint64(&ca.state.localSequenceNumber[0], recordlayer.MaxSequenceNumber+1)

		// Try to send handshake packet.
		werr := ca.writePackets(ctx, []*packet{
			{
				record: &recordlayer.RecordLayer{
					Header: recordlayer.Header{
						Version: protocol.Version1_2,
					},
					Content: &handshake.Handshake{
						Message: &handshake.MessageClientHello{
							Version:            protocol.Version1_2,
							Cookie:             make([]byte, 64),
							CipherSuiteIDs:     cipherSuiteIDs(defaultCipherSuites()),
							CompressionMethods: defaultCompressionMethods(),
						},
					},
				},
			},
		})
		assert.ErrorIs(t, werr, errSequenceNumberOverflow,
			"Connection must fail when handshake packet reaches maximum sequence num")
		assert.NoError(t, ca.Close())
		assert.NoError(t, cb.Close())
	})
}

func pipeMemory() (*Conn, *Conn, error) {
	// In memory pipe
	ca, cb := dpipe.Pipe()

	return pipeConn(ca, cb)
}

func pipeConn(ca, cb net.Conn) (*Conn, *Conn, error) {
	type result struct {
		c   *Conn
		err error
	}

	resultCh := make(chan result)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Setup client
	go func() {
		client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
			SRTPProtectionProfiles: []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
		}, true)
		resultCh <- result{client, err}
	}()

	// Setup server
	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
		SRTPProtectionProfiles: []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
	}, true)
	if err != nil {
		return nil, nil, err
	}

	// Receive client
	res := <-resultCh
	if res.err != nil {
		_ = server.Close()

		return nil, nil, res.err
	}

	return res.c, server, nil
}

func testClient(
	ctx context.Context,
	pktConn net.PacketConn,
	rAddr net.Addr,
	cfg *Config,
	generateCertificate bool,
) (*Conn, error) {
	if generateCertificate {
		clientCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{clientCert}
	}
	cfg.InsecureSkipVerify = true
	conn, err := Client(pktConn, rAddr, cfg)
	if err != nil {
		return nil, err
	}

	return conn, conn.HandshakeContext(ctx)
}

func testServer(
	ctx context.Context,
	c net.PacketConn,
	rAddr net.Addr,
	cfg *Config,
	generateCertificate bool,
) (*Conn, error) {
	if generateCertificate {
		serverCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{serverCert}
	}
	conn, err := Server(c, rAddr, cfg)
	if err != nil {
		return nil, err
	}

	return conn, conn.HandshakeContext(ctx)
}

func sendClientHello(cookie []byte, ca net.Conn, sequenceNumber uint64, extensions []extension.Extension) error {
	packet, err := (&recordlayer.RecordLayer{
		Header: recordlayer.Header{
			Version:        protocol.Version1_2,
			SequenceNumber: sequenceNumber,
		},
		Content: &handshake.Handshake{
			Header: handshake.Header{
				MessageSequence: uint16(sequenceNumber), //nolint:gosec // G115
			},
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				Cookie:             cookie,
				CipherSuiteIDs:     cipherSuiteIDs(defaultCipherSuites()),
				CompressionMethods: defaultCompressionMethods(),
				Extensions:         extensions,
			},
		},
	}).Marshal()
	if err != nil {
		return err
	}

	if _, err = ca.Write(packet); err != nil {
		return err
	}

	return nil
}

func TestHandshakeWithAlert(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cases := map[string]struct {
		configServer, configClient *Config
		errServer, errClient       error
	}{
		"CipherSuiteNoIntersection": {
			configServer: &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			},
			configClient: &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			},
			errServer: errCipherSuiteNoIntersection,
			errClient: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
		},
		"SignatureSchemesNoIntersection": {
			configServer: &Config{
				CipherSuites:     []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
			},
			configClient: &Config{
				CipherSuites:     []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP521AndSHA512},
			},
			errServer: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			errClient: errNoAvailableSignatureSchemes,
		},
	}

	for name, testCase := range cases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			clientErr := make(chan error, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				_, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), testCase.configClient, true)
				clientErr <- err
			}()

			_, errServer := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), testCase.configServer, true)
			assert.ErrorIs(t, errServer, testCase.errServer)
			assert.ErrorIs(t, <-clientErr, testCase.errClient)
		})
	}
}

func TestHandshakeWithInvalidRecord(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		c   *Conn
		err error
	}
	clientErr := make(chan result, 1)
	ca, cb := dpipe.Pipe()
	caWithInvalidRecord := &connWithCallback{Conn: ca}

	var msgSeq atomic.Int32
	// Send invalid record after first message
	caWithInvalidRecord.onWrite = func([]byte) {
		if msgSeq.Add(1) == 2 {
			_, err := ca.Write([]byte{0x01, 0x02})
			assert.NoError(t, err)
		}
	}
	go func() {
		client, err := testClient(
			ctx,
			dtlsnet.PacketConnFromConn(caWithInvalidRecord),
			caWithInvalidRecord.RemoteAddr(),
			&Config{CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}},
			true,
		)
		clientErr <- result{client, err}
	}()

	server, errServer := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
		CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}, true)

	errClient := <-clientErr

	defer func() {
		if server != nil {
			assert.NoError(t, server.Close())
		}

		if errClient.c != nil {
			assert.NoError(t, errClient.c.Close())
		}
	}()

	assert.NoError(t, errServer)
	assert.NoError(t, errClient.err)
}

func TestExportKeyingMaterial(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	var rand [28]byte
	exportLabel := "EXTRACTOR-dtls_srtp"

	expectedServerKey := []byte{0x61, 0x09, 0x9d, 0x7d, 0xcb, 0x08, 0x52, 0x2c, 0xe7, 0x7b}
	expectedClientKey := []byte{0x87, 0xf0, 0x40, 0x02, 0xf6, 0x1c, 0xf1, 0xfe, 0x8c, 0x77}

	conn := &Conn{
		state: State{
			localRandom:         handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand},
			remoteRandom:        handshake.Random{GMTUnixTime: time.Unix(1000, 0), RandomBytes: rand},
			localSequenceNumber: []uint64{0, 0},
			cipherSuite:         &ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{},
		},
	}
	conn.setLocalEpoch(0)
	conn.setRemoteEpoch(0)

	state, ok := conn.ConnectionState()
	assert.True(t, ok)

	_, err := state.ExportKeyingMaterial(exportLabel, nil, 0)
	assert.ErrorIs(t, err, errHandshakeInProgress, "ExportKeyingMaterial when epoch == 0 error mismatch")

	conn.setLocalEpoch(1)
	state, ok = conn.ConnectionState()
	assert.True(t, ok)

	_, err = state.ExportKeyingMaterial(exportLabel, []byte{0x00}, 0)
	assert.ErrorIs(t, err, errContextUnsupported, "ExportKeyingMaterial with context mismatch")

	for k := range invalidKeyingLabels() {
		state, ok = conn.ConnectionState()
		assert.True(t, ok)

		_, err = state.ExportKeyingMaterial(k, nil, 0)
		assert.ErrorIs(t, err, errReservedExportKeyingMaterial, "ExportKeyingMaterial reserved label mismatch")
	}

	state, ok = conn.ConnectionState()
	assert.True(t, ok)

	keyingMaterial, err := state.ExportKeyingMaterial(exportLabel, nil, 10)
	assert.NoError(t, err, "ExportingKeyingMaterial as server error")
	assert.Equal(t, expectedServerKey, keyingMaterial, "ExportKeyingMaterial client export mismatch")

	conn.state.isClient = true
	state, ok = conn.ConnectionState()
	assert.True(t, ok)

	keyingMaterial, err = state.ExportKeyingMaterial(exportLabel, nil, 10)
	assert.NoError(t, err)
	assert.Equal(t, expectedClientKey, keyingMaterial, "ExportKeyingMaterial client report mismatch")
}

func TestPSK(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                   string
		ClientIdentity         []byte
		ServerIdentity         []byte
		CipherSuites           []CipherSuiteID
		ClientVerifyConnection func(*State) error
		ServerVerifyConnection func(*State) error
		WantFail               bool
		ExpectedServerErr      string
		ExpectedClientErr      string
	}{
		{
			Name:           "Server identity specified",
			ServerIdentity: []byte("Test Identity"),
			ClientIdentity: []byte("Client Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		},
		{
			Name:           "Server identity specified - Server verify connection fails",
			ServerIdentity: []byte("Test Identity"),
			ClientIdentity: []byte("Client Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
			ServerVerifyConnection: func(*State) error {
				return errExample
			},
			WantFail:          true,
			ExpectedServerErr: errExample.Error(),
			ExpectedClientErr: alert.BadCertificate.String(),
		},
		{
			Name:           "Server identity specified - Client verify connection fails",
			ServerIdentity: []byte("Test Identity"),
			ClientIdentity: []byte("Client Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
			ClientVerifyConnection: func(*State) error {
				return errExample
			},
			WantFail:          true,
			ExpectedServerErr: alert.BadCertificate.String(),
			ExpectedClientErr: errExample.Error(),
		},
		{
			Name:           "Server identity nil",
			ServerIdentity: nil,
			ClientIdentity: []byte("Client Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		},
		{
			Name:           "TLS_PSK_WITH_AES_128_CBC_SHA256",
			ServerIdentity: nil,
			ClientIdentity: []byte("Client Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CBC_SHA256},
		},
		{
			Name:           "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
			ServerIdentity: nil,
			ClientIdentity: []byte("Client Identity"),
			CipherSuites:   []CipherSuiteID{TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256},
		},
		{
			Name:           "Client identity empty",
			ServerIdentity: nil,
			ClientIdentity: []byte{},
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			type result struct {
				c   *Conn
				err error
			}
			clientRes := make(chan result, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				conf := &Config{
					PSK: func(hint []byte) ([]byte, error) {
						if !bytes.Equal(test.ServerIdentity, hint) {
							return nil, fmt.Errorf( //nolint:goerr113
								"TestPSK: Client got invalid identity expected(% 02x) actual(% 02x)",
								test.ServerIdentity, hint,
							)
						}

						return []byte{0xAB, 0xC1, 0x23}, nil
					},
					PSKIdentityHint:  test.ClientIdentity,
					CipherSuites:     test.CipherSuites,
					VerifyConnection: test.ClientVerifyConnection,
				}

				c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), conf, false)
				clientRes <- result{c, err}
			}()

			config := &Config{
				PSK: func(hint []byte) ([]byte, error) {
					t.Log(hint)
					if !bytes.Equal(test.ClientIdentity, hint) {
						return nil, fmt.Errorf("%w: expected(% 02x) actual(% 02x)", errTestPSKInvalidIdentity, test.ClientIdentity, hint)
					}

					return []byte{0xAB, 0xC1, 0x23}, nil
				},
				PSKIdentityHint:  test.ServerIdentity,
				CipherSuites:     test.CipherSuites,
				VerifyConnection: test.ServerVerifyConnection,
			}

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, false)
			if test.WantFail {
				res := <-clientRes
				assert.Error(t, err)
				assert.True(t, strings.Contains(err.Error(), test.ExpectedServerErr), "TestPSK: Server expected error mismatch")
				assert.Error(t, res.err, "TestPSK: Client expected error mismatch")
				assert.True(t, strings.Contains(res.err.Error(), test.ExpectedClientErr),
					"TestPSK: Client expeected error mismatch")

				return
			}
			assert.NoError(t, err)

			state, ok := server.ConnectionState()
			assert.True(t, ok, "TestPSK: Server ConnectionState failed")

			actualPSKIdentityHint := state.IdentityHint
			assert.Equal(t, test.ClientIdentity, actualPSKIdentityHint, "TestPSK: Server ClientPSKIdentity Mismatch")

			defer func() {
				_ = server.Close()
			}()

			res := <-clientRes
			assert.NoError(t, res.err)
			assert.NoError(t, res.c.Close())
		})
	}
}

func TestPSKHintFail(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	serverAlertError := &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InternalError}}
	pskRejected := errPSKRejected

	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientErr := make(chan error, 1)

	ca, cb := dpipe.Pipe()
	go func() {
		conf := &Config{
			PSK: func([]byte) ([]byte, error) {
				return nil, pskRejected
			},
			PSKIdentityHint: []byte{},
			CipherSuites:    []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		}

		_, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), conf, false)
		clientErr <- err
	}()

	config := &Config{
		PSK: func([]byte) ([]byte, error) {
			return nil, pskRejected
		},
		PSKIdentityHint: []byte{},
		CipherSuites:    []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
	}

	_, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, false)
	assert.ErrorIs(t, err, serverAlertError, "TestPSK: Server should fail with alert error")
	assert.ErrorIs(t, <-clientErr, pskRejected, "TestPSK: Client should fail with pskRejected error")
}

// Assert that ServerKeyExchange is only sent if Identity is set on server side.
func TestPSKServerKeyExchange(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name        string
		SetIdentity bool
	}{
		{
			Name:        "Server Identity Set",
			SetIdentity: true,
		},
		{
			Name:        "Server Not Identity Set",
			SetIdentity: false,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			gotServerKeyExchange := false

			clientErr := make(chan error, 1)
			ca, cb := dpipe.Pipe()
			cbAnalyzer := &connWithCallback{Conn: cb}
			cbAnalyzer.onWrite = func(in []byte) {
				messages, err := recordlayer.UnpackDatagram(in)
				assert.NoError(t, err)

				for i := range messages {
					h := &handshake.Handshake{}
					_ = h.Unmarshal(messages[i][recordlayer.FixedHeaderSize:])

					if h.Header.Type == handshake.TypeServerKeyExchange {
						gotServerKeyExchange = true
					}
				}
			}

			go func() {
				conf := &Config{
					PSK: func([]byte) ([]byte, error) {
						return []byte{0xAB, 0xC1, 0x23}, nil
					},
					PSKIdentityHint: []byte{0xAB, 0xC1, 0x23},
					CipherSuites:    []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
				}

				if client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), conf, false); err != nil {
					clientErr <- err
				} else {
					clientErr <- client.Close() //nolint
				}
			}()

			config := &Config{
				PSK: func([]byte) ([]byte, error) {
					return []byte{0xAB, 0xC1, 0x23}, nil
				},
				CipherSuites: []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
			}
			if test.SetIdentity {
				config.PSKIdentityHint = []byte{0xAB, 0xC1, 0x23}
			}

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cbAnalyzer), cbAnalyzer.RemoteAddr(), config, false)
			assert.NoError(t, err)
			assert.NoError(t, server.Close())
			assert.NoError(t, <-clientErr, "TestPSK: Client erro")
			assert.Equal(t, test.SetIdentity, gotServerKeyExchange)
		})
	}
}

func TestClientTimeout(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	clientErr := make(chan error, 1)

	ca, _ := dpipe.Pipe()
	go func() {
		conf := &Config{}

		c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), conf, true)
		if err == nil {
			_ = c.Close() //nolint:contextcheck
		}
		clientErr <- err
	}()

	// no server!
	err := <-clientErr
	var netErr net.Error
	assert.ErrorAs(t, err, &netErr, "Client error exp(Temporary network error) failed")
	assert.True(t, netErr.Timeout(), "Client error exp(Timeout) failed")
}

func TestSRTPConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                          string
		ClientSRTP                    []SRTPProtectionProfile
		ServerSRTP                    []SRTPProtectionProfile
		ClientSRTPMasterKeyIdentifier []byte
		ServerSRTPMasterKeyIdentifier []byte
		ExpectedProfile               SRTPProtectionProfile
		WantClientError               error
		WantServerError               error
	}{
		{
			Name:            "No SRTP in use",
			ClientSRTP:      nil,
			ServerSRTP:      nil,
			ExpectedProfile: 0,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name:                          "SRTP both ends",
			ClientSRTP:                    []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ServerSRTP:                    []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile:               SRTP_AES128_CM_HMAC_SHA1_80,
			ClientSRTPMasterKeyIdentifier: []byte("ClientSRTPMKI"),
			ServerSRTPMasterKeyIdentifier: []byte("ServerSRTPMKI"),
			WantClientError:               nil,
			WantServerError:               nil,
		},
		{
			Name:            "SRTP client only",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ServerSRTP:      nil,
			ExpectedProfile: 0,
			WantClientError: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			WantServerError: errServerNoMatchingSRTPProfile,
		},
		{
			Name:            "SRTP server only",
			ClientSRTP:      nil,
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile: 0,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name:            "Multiple Suites",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AES128_CM_HMAC_SHA1_32},
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AES128_CM_HMAC_SHA1_32},
			ExpectedProfile: SRTP_AES128_CM_HMAC_SHA1_80,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name:            "Multiple Suites, Client Chooses",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AES128_CM_HMAC_SHA1_32},
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_32, SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile: SRTP_AES128_CM_HMAC_SHA1_80,
			WantClientError: nil,
			WantServerError: nil,
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		type result struct {
			c   *Conn
			err error
		}
		resultCh := make(chan result)

		go func() {
			client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
				SRTPProtectionProfiles: test.ClientSRTP, SRTPMasterKeyIdentifier: test.ServerSRTPMasterKeyIdentifier,
			}, true)
			resultCh <- result{client, err}
		}()

		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
			SRTPProtectionProfiles: test.ServerSRTP, SRTPMasterKeyIdentifier: test.ClientSRTPMasterKeyIdentifier,
		}, true)
		assert.ErrorIs(t, err, test.WantServerError, "TestSRTPConfiguration: Server Error Mismatch")

		if err == nil {
			defer func() {
				_ = server.Close()
			}()
		}

		res := <-resultCh
		if res.err == nil {
			defer func() {
				_ = res.c.Close()
			}()
		}
		assert.ErrorIsf(t, res.err, test.WantClientError, "TestSRTPConfiguration: Client Error Mismatch '%s'", test.Name)
		if res.c == nil {
			return
		}

		actualClientSRTP, _ := res.c.SelectedSRTPProtectionProfile()
		assert.Equalf(t, test.ExpectedProfile, actualClientSRTP,
			"TestSRTPConfiguration: Client SRTPProtectionProfile Mismatch '%s'", test.Name)

		actualServerSRTP, _ := server.SelectedSRTPProtectionProfile()
		assert.Equalf(t, test.ExpectedProfile, actualServerSRTP,
			"TestSRTPConfiguration: Server SRTPProtectionProfile Mismatch '%s'", test.Name)

		actualServerMKI, _ := server.RemoteSRTPMasterKeyIdentifier()
		assert.Truef(t, bytes.Equal(test.ServerSRTPMasterKeyIdentifier, actualServerMKI),
			"TestSRTPConfiguration: Server SRTPMKI Mismatch '%s'", test.Name)

		actualClientMKI, _ := res.c.RemoteSRTPMasterKeyIdentifier()
		assert.Truef(t, bytes.Equal(test.ClientSRTPMasterKeyIdentifier, actualClientMKI),
			"TestSRTPConfiguration: Client SRTPMKI Mismatch '%s'", test.Name)
	}
}

func TestClientCertificate(t *testing.T) { //nolint:gocyclo,cyclop,maintidx
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	srvCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	srvCAPool := x509.NewCertPool()
	srvCertificate, err := x509.ParseCertificate(srvCert.Certificate[0])
	assert.NoError(t, err)

	srvCAPool.AddCert(srvCertificate)

	cert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	assert.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(certificate)

	t.Run("parallel", func(t *testing.T) { // sync routines to check routine leak
		tests := map[string]struct {
			clientCfg *Config
			serverCfg *Config
			wantErr   bool
		}{
			"NoClientCert": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   NoClientCert,
					ClientCAs:    caPool,
				},
			},
			"NoClientCert_ServerVerifyConnectionFails": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   NoClientCert,
					ClientCAs:    caPool,
					VerifyConnection: func(*State) error {
						return errExample
					},
				},
				wantErr: true,
			},
			"NoClientCert_ClientVerifyConnectionFails": {
				clientCfg: &Config{RootCAs: srvCAPool, VerifyConnection: func(*State) error {
					return errExample
				}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   NoClientCert,
					ClientCAs:    caPool,
				},
				wantErr: true,
			},
			"NoClientCert_cert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequireAnyClientCert,
				},
			},
			"RequestClientCert_cert_sigscheme": { // specify signature algorithm
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP521AndSHA512},
					Certificates:     []tls.Certificate{srvCert},
					ClientAuth:       RequestClientCert,
				},
			},
			"RequestClientCert_cert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequestClientCert,
				},
			},
			"RequestClientCert_no_cert": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequestClientCert,
					ClientCAs:    caPool,
				},
			},
			"RequireAnyClientCert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequireAnyClientCert,
				},
			},
			"RequireAnyClientCert_error": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequireAnyClientCert,
				},
				wantErr: true,
			},
			"VerifyClientCertIfGiven_no_cert": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   VerifyClientCertIfGiven,
					ClientCAs:    caPool,
				},
			},
			"VerifyClientCertIfGiven_cert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   VerifyClientCertIfGiven,
					ClientCAs:    caPool,
				},
			},
			"VerifyClientCertIfGiven_error": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   VerifyClientCertIfGiven,
				},
				wantErr: true,
			},
			"RequireAndVerifyClientCert": {
				clientCfg: &Config{
					RootCAs:      srvCAPool,
					Certificates: []tls.Certificate{cert},
					VerifyConnection: func(s *State) error {
						if ok := bytes.Equal(s.PeerCertificates[0], srvCertificate.Raw); !ok {
							return errExample
						}

						return nil
					},
				},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequireAndVerifyClientCert,
					ClientCAs:    caPool,
					VerifyConnection: func(s *State) error {
						if ok := bytes.Equal(s.PeerCertificates[0], certificate.Raw); !ok {
							return errExample
						}

						return nil
					},
				},
			},
			"RequireAndVerifyClientCert_callbacks": {
				clientCfg: &Config{
					RootCAs: srvCAPool,
					// Certificates:   []tls.Certificate{cert},
					GetClientCertificate: func(*CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil },
				},
				serverCfg: &Config{
					GetCertificate: func(*ClientHelloInfo) (*tls.Certificate, error) { return &srvCert, nil },
					// Certificates:   []tls.Certificate{srvCert},
					ClientAuth: RequireAndVerifyClientCert,
					ClientCAs:  caPool,
				},
			},
		}
		for name, tt := range tests {
			tt := tt
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()
				type result struct {
					c          *Conn
					err, hserr error
				}
				c := make(chan result)

				go func() {
					client, err := Client(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), tt.clientCfg)
					c <- result{client, err, client.Handshake()}
				}()

				server, err := Server(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), tt.serverCfg)
				hserr := server.Handshake()
				res := <-c
				defer func() {
					if err == nil {
						_ = server.Close()
					}
					if res.err == nil {
						_ = res.c.Close()
					}
				}()

				if tt.wantErr {
					assert.True(t, err != nil || hserr != nil, "Error expected")

					return // Error expected, test succeeded
				}
				assert.NoError(t, err)
				assert.NoError(t, res.err)

				state, ok := server.ConnectionState()
				assert.True(t, ok, "Server connection state not available")

				actualClientCert := state.PeerCertificates
				//nolint:nestif
				if tt.serverCfg.ClientAuth == RequireAnyClientCert ||
					tt.serverCfg.ClientAuth == RequireAndVerifyClientCert {
					assert.NotNil(t, actualClientCert, "Client did not provide a certificate")

					var cfgCert [][]byte
					if len(tt.clientCfg.Certificates) > 0 {
						cfgCert = tt.clientCfg.Certificates[0].Certificate
					}
					if tt.clientCfg.GetClientCertificate != nil {
						crt, err := tt.clientCfg.GetClientCertificate(&CertificateRequestInfo{})
						assert.NoError(t, err, "Server configuration did not provide a certificate")

						cfgCert = crt.Certificate
					}

					assert.NotEmpty(t, cfgCert, "Client certificate was not communicated correctly")
					assert.Equal(t, actualClientCert[0], cfgCert[0], "Client certificate was not communicated correctly")
				}
				if tt.serverCfg.ClientAuth == NoClientCert {
					assert.Nil(t, actualClientCert, "Client certificate wasn't expected")
				}

				clientState, ok := res.c.ConnectionState()
				assert.True(t, ok, "Client connection state not available")

				actualServerCert := clientState.PeerCertificates
				assert.NotNil(t, actualServerCert, "server did not provide a certificate")

				var cfgCert [][]byte
				if len(tt.serverCfg.Certificates) > 0 {
					cfgCert = tt.serverCfg.Certificates[0].Certificate
				}
				if tt.serverCfg.GetCertificate != nil {
					crt, err := tt.serverCfg.GetCertificate(&ClientHelloInfo{})
					assert.NoError(t, err, "Server configuration did not provide a certificate")
					cfgCert = crt.Certificate
				}
				assert.NotEmpty(t, cfgCert, "Server certificate was not communicated correctly")
				assert.Equal(t, actualServerCert[0], cfgCert[0], "Server certificate was not communicated correctly")
			})
		}
	})
}

func TestConnectionID(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	clientCID := []byte{5, 77, 33, 24, 93, 27, 45, 81}
	serverCID := []byte{64, 24, 73, 2, 17, 96, 38, 59}
	cidEcho := func(echo []byte) func() []byte {
		return func() []byte {
			return echo
		}
	}
	tests := map[string]struct {
		clientCfg          *Config
		serverCfg          *Config
		clientConnectionID []byte
		serverConnectionID []byte
	}{
		"BidirectionalConnectionIDs": {
			clientCfg: &Config{
				ConnectionIDGenerator: cidEcho(clientCID),
			},
			serverCfg: &Config{
				ConnectionIDGenerator: cidEcho(serverCID),
			},
			clientConnectionID: clientCID,
			serverConnectionID: serverCID,
		},
		"BothSupportOnlyClientSends": {
			clientCfg: &Config{
				ConnectionIDGenerator: cidEcho(nil),
			},
			serverCfg: &Config{
				ConnectionIDGenerator: cidEcho(serverCID),
			},
			serverConnectionID: serverCID,
		},
		"BothSupportOnlyServerSends": {
			clientCfg: &Config{
				ConnectionIDGenerator: cidEcho(clientCID),
			},
			serverCfg: &Config{
				ConnectionIDGenerator: cidEcho(nil),
			},
			clientConnectionID: clientCID,
		},
		"ClientDoesNotSupport": {
			clientCfg: &Config{},
			serverCfg: &Config{
				ConnectionIDGenerator: cidEcho(serverCID),
			},
		},
		"ServerDoesNotSupport": {
			clientCfg: &Config{
				ConnectionIDGenerator: cidEcho(clientCID),
			},
			serverCfg: &Config{},
		},
		"NeitherSupport": {
			clientCfg: &Config{},
			serverCfg: &Config{},
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			type result struct {
				c   *Conn
				err error
			}
			c := make(chan result)

			go func() {
				client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), tt.clientCfg, true)
				c <- result{client, err}
			}()

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), tt.serverCfg, true)
			assert.NoError(t, err)

			res := <-c
			assert.NoError(t, res.err)
			defer func() {
				if err == nil {
					_ = server.Close()
				}
				if res.err == nil {
					_ = res.c.Close()
				}
			}()

			assert.True(t, bytes.Equal(tt.clientConnectionID, res.c.state.getLocalConnectionID()),
				"Unexpected client local connection ID")
			assert.True(t, bytes.Equal(tt.serverConnectionID, res.c.state.remoteConnectionID),
				"Unexpected client remote connection ID")
			assert.True(t, bytes.Equal(tt.serverConnectionID, server.state.getLocalConnectionID()),
				"Unexpected server local connection ID")
			assert.True(t, bytes.Equal(tt.clientConnectionID, server.state.remoteConnectionID),
				"Unexpected server remote connection ID")
		})
	}
}

func TestExtendedMasterSecret(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	tests := map[string]struct {
		clientCfg         *Config
		serverCfg         *Config
		expectedClientErr error
		expectedServerErr error
	}{
		"Request_Request_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Request_Require_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Request_Disable_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Request_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Require_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Disable_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			expectedClientErr: errClientRequiredButNoServerEMS,
			expectedServerErr: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
		},
		"Disable_Request_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Disable_Require_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			expectedClientErr: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			expectedServerErr: errServerRequiredButNoClientEMS,
		},
		"Disable_Disable_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			type result struct {
				c   *Conn
				err error
			}
			c := make(chan result)

			go func() {
				client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), tt.clientCfg, true)
				c <- result{client, err}
			}()

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), tt.serverCfg, true)
			res := <-c
			defer func() {
				if err == nil {
					_ = server.Close()
				}
				if res.err == nil {
					_ = res.c.Close()
				}
			}()
			assert.ErrorIs(t, res.err, tt.expectedClientErr)
			assert.ErrorIs(t, err, tt.expectedServerErr)
		})
	}
}

func TestServerCertificate(t *testing.T) { //nolint:cyclop
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	assert.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(certificate)

	t.Run("parallel", func(t *testing.T) { // sync routines to check routine leak
		tests := map[string]struct {
			clientCfg *Config
			serverCfg *Config
			wantErr   bool
		}{
			"no_ca": {
				clientCfg: &Config{},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
				wantErr:   true,
			},
			"good_ca": {
				clientCfg: &Config{RootCAs: caPool},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
			},
			"no_ca_skip_verify": {
				clientCfg: &Config{InsecureSkipVerify: true},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
			},
			"good_ca_skip_verify_custom_verify_peer": {
				clientCfg: &Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{cert},
					ClientAuth:   RequireAnyClientCert,
					VerifyPeerCertificate: func(_ [][]byte, chain [][]*x509.Certificate) error {
						if len(chain) != 0 {
							return errNotExpectedChain
						}

						return nil
					},
				},
			},
			"good_ca_verify_custom_verify_peer": {
				clientCfg: &Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					ClientCAs:    caPool,
					Certificates: []tls.Certificate{cert},
					ClientAuth:   RequireAndVerifyClientCert,
					VerifyPeerCertificate: func(_ [][]byte, chain [][]*x509.Certificate) error {
						if len(chain) == 0 {
							return errExpecedChain
						}

						return nil
					},
				},
			},
			"good_ca_custom_verify_peer": {
				clientCfg: &Config{
					RootCAs: caPool,
					VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
						return errWrongCert
					},
				},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
				wantErr:   true,
			},
			"server_name": {
				clientCfg: &Config{RootCAs: caPool, ServerName: certificate.Subject.CommonName},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
			},
			"server_name_error": {
				clientCfg: &Config{RootCAs: caPool, ServerName: "barfoo"},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
				wantErr:   true,
			},
		}
		for name, tt := range tests {
			tt := tt
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()

				type result struct {
					c          *Conn
					err, hserr error
				}
				srvCh := make(chan result)
				go func() {
					s, err := Server(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), tt.serverCfg)
					srvCh <- result{s, err, s.Handshake()}
				}()

				cli, err := Client(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), tt.clientCfg)
				hserr := cli.Handshake()
				if err == nil {
					_ = cli.Close()
				}
				if tt.wantErr {
					assert.True(t, err != nil || hserr != nil, "Expected error")
				} else {
					assert.NoError(t, err, "Client connection failed")
					assert.NoError(t, hserr, "Client handshake failed")
				}

				srv := <-srvCh
				if srv.err == nil {
					_ = srv.c.Close()
				}
			})
		}
	})
}

func TestCipherSuiteConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                    string
		ClientCipherSuites      []CipherSuiteID
		ServerCipherSuites      []CipherSuiteID
		WantClientError         error
		WantServerError         error
		WantSelectedCipherSuite CipherSuiteID
	}{
		{
			Name:               "No CipherSuites specified",
			ClientCipherSuites: nil,
			ServerCipherSuites: nil,
			WantClientError:    nil,
			WantServerError:    nil,
		},
		{
			Name:               "Invalid CipherSuite",
			ClientCipherSuites: []CipherSuiteID{0x00},
			ServerCipherSuites: []CipherSuiteID{0x00},
			WantClientError:    &invalidCipherSuiteError{0x00},
			WantServerError:    &invalidCipherSuiteError{0x00},
		},
		{
			Name:                    "Valid CipherSuites specified",
			ClientCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		{
			Name:               "CipherSuites mismatch",
			ClientCipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
			WantClientError:    &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			WantServerError:    errCipherSuiteNoIntersection,
		},
		{
			Name:                    "Valid CipherSuites CCM specified",
			ClientCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_CCM},
			ServerCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_CCM},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		},
		{
			Name:                    "Valid CipherSuites CCM-8 specified",
			ClientCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8},
			ServerCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		},
		{
			Name: "Server supports subset of client suites",
			ClientCipherSuites: []CipherSuiteID{
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			},
			ServerCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			type result struct {
				c   *Conn
				err error
			}
			resultCh := make(chan result)

			go func() {
				client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
					CipherSuites: test.ClientCipherSuites,
				}, true)
				resultCh <- result{client, err}
			}()

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
				CipherSuites: test.ServerCipherSuites,
			}, true)
			if err == nil {
				defer func() {
					_ = server.Close()
				}()
			}
			assert.ErrorIsf(t, err, test.WantServerError, "TestCipherSuiteConfiguration: Server Error Mismatch '%s'", test.Name)

			res := <-resultCh
			if err == nil {
				assert.NoError(t, server.Close())
				assert.NoError(t, res.c.Close())
			}
			assert.ErrorIsf(t, res.err, test.WantClientError, "TestCipherSuiteConfiguration: Client Error Mismatch '%s'")
			if test.WantSelectedCipherSuite != 0x00 {
				assert.Equal(t, test.WantSelectedCipherSuite, res.c.state.cipherSuite.ID(),
					"TestCipherSuiteConfiguration: Server Selected Bad Cipher Suite '%s'", test.Name)
			}
		})
	}
}

func TestCertificateAndPSKServer(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name      string
		ClientPSK bool
	}{
		{
			Name:      "Client uses PKI",
			ClientPSK: false,
		},
		{
			Name:      "Client uses PSK",
			ClientPSK: true,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			type result struct {
				c   *Conn
				err error
			}
			resultCh := make(chan result)

			go func() {
				config := &Config{CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}
				if test.ClientPSK {
					config.PSK = func([]byte) ([]byte, error) {
						return []byte{0x00, 0x01, 0x02}, nil
					}
					config.PSKIdentityHint = []byte{0x00}
					config.CipherSuites = []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256}
				}

				client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), config, false)
				resultCh <- result{client, err}
			}()

			config := &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_PSK_WITH_AES_128_GCM_SHA256},
				PSK: func([]byte) ([]byte, error) {
					return []byte{0x00, 0x01, 0x02}, nil
				},
			}

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true)
			assert.NoErrorf(t, err, "TestCertificateAndPSKServer: Server Error Mismatch '%s'", test.Name)
			if err != nil {
				defer func() {
					assert.NoError(t, server.Close())
				}()
			}

			res := <-resultCh
			assert.NoErrorf(t, res.err, "TestCertificateAndPSKServer: Server Error Mismatch '%s'", test.Name)
			assert.NoError(t, server.Close())
			assert.NoError(t, res.c.Close())
		})
	}
}

func TestPSKConfiguration(t *testing.T) { //nolint:cyclop
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                 string
		ClientHasCertificate bool
		ServerHasCertificate bool
		ClientPSK            PSKCallback
		ServerPSK            PSKCallback
		ClientPSKIdentity    []byte
		ServerPSKIdentity    []byte
		WantClientError      error
		WantServerError      error
	}{
		{
			Name:                 "PSK and no certificate specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      errNoAvailablePSKCipherSuite,
			WantServerError:      errNoAvailablePSKCipherSuite,
		},
		{
			Name:                 "PSK and certificate specified",
			ClientHasCertificate: true,
			ServerHasCertificate: true,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      errNoAvailablePSKCipherSuite,
			WantServerError:      errNoAvailablePSKCipherSuite,
		},
		{
			Name:                 "PSK and no identity specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    nil,
			ServerPSKIdentity:    nil,
			WantClientError:      errPSKAndIdentityMustBeSetForClient,
			WantServerError:      errNoAvailablePSKCipherSuite,
		},
		{
			Name:                 "No PSK and identity specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            nil,
			ServerPSK:            nil,
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      errIdentityNoPSK,
			WantServerError:      errIdentityNoPSK,
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		type result struct {
			c   *Conn
			err error
		}
		resultCh := make(chan result)

		go func() {
			client, err := testClient(
				ctx,
				dtlsnet.PacketConnFromConn(ca),
				ca.RemoteAddr(),
				&Config{PSK: test.ClientPSK, PSKIdentityHint: test.ClientPSKIdentity},
				test.ClientHasCertificate,
			)
			resultCh <- result{client, err}
		}()

		_, err := testServer(
			ctx,
			dtlsnet.PacketConnFromConn(cb),
			cb.RemoteAddr(),
			&Config{PSK: test.ServerPSK, PSKIdentityHint: test.ServerPSKIdentity},
			test.ServerHasCertificate,
		)
		if err != nil || test.WantServerError != nil {
			if !(err != nil && test.WantServerError != nil && err.Error() == test.WantServerError.Error()) {
				assert.Failf(t, "TestPSKConfiguration", "Server Error Mismatch '%s'", test.Name)
			}
		}

		res := <-resultCh
		if res.err != nil || test.WantClientError != nil {
			if !(res.err != nil && test.WantClientError != nil && res.err.Error() == test.WantClientError.Error()) {
				assert.Failf(t, "TestPSKConfiguration", "Client Error Mismatch '%s'", test.Name)
			}
		}
	}
}

func TestServerTimeout(t *testing.T) { //nolint:cyclop
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cookie := make([]byte, 20)
	_, err := rand.Read(cookie)
	assert.NoError(t, err)

	var rand [28]byte
	random := handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand}

	cipherSuites := []CipherSuite{
		&ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{},
		&ciphersuite.TLSEcdheRsaWithAes128GcmSha256{},
	}

	extensions := []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: []signaturehash.Algorithm{
				{Hash: hash.SHA256, Signature: signature.ECDSA},
				{Hash: hash.SHA384, Signature: signature.ECDSA},
				{Hash: hash.SHA512, Signature: signature.ECDSA},
				{Hash: hash.SHA256, Signature: signature.RSA},
				{Hash: hash.SHA384, Signature: signature.RSA},
				{Hash: hash.SHA512, Signature: signature.RSA},
			},
		},
		&extension.SupportedEllipticCurves{
			EllipticCurves: []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384},
		},
		&extension.SupportedPointFormats{
			PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
		},
	}

	record := &recordlayer.RecordLayer{
		Header: recordlayer.Header{
			SequenceNumber: 0,
			Version:        protocol.Version1_2,
		},
		Content: &handshake.Handshake{
			// sequenceNumber and messageSequence line up, may need to be re-evaluated
			Header: handshake.Header{
				MessageSequence: 0,
			},
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				Cookie:             cookie,
				Random:             random,
				CipherSuiteIDs:     cipherSuiteIDs(cipherSuites),
				CompressionMethods: defaultCompressionMethods(),
				Extensions:         extensions,
			},
		},
	}

	packet, err := record.Marshal()
	assert.NoError(t, err)

	ca, cb := dpipe.Pipe()
	defer func() {
		assert.NoError(t, ca.Close())
	}()

	// Client reader
	caReadChan := make(chan []byte, 1000)
	go func() {
		for {
			data := make([]byte, 8192)
			n, err := ca.Read(data)
			if err != nil {
				return
			}

			caReadChan <- data[:n]
		}
	}()

	// Start sending ClientHello packets until server responds with first packet
	go func() {
		for {
			select {
			case <-time.After(10 * time.Millisecond):
				_, err := ca.Write(packet)
				if err != nil {
					return
				}
			case <-caReadChan:
				// Once we receive the first reply from the server, stop
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	config := &Config{
		CipherSuites:   []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		FlightInterval: 100 * time.Millisecond,
	}

	_, serverErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true)
	var netErr net.Error
	assert.ErrorAsf(t, serverErr, &netErr, "Client error exp(Temporary network error) failed(%v)", serverErr)
	assert.Truef(t, netErr.Timeout(), "Client error exp(Temporary network error) failed(%v)", serverErr)

	// Wait a little longer to ensure no additional messages have been sent by the server
	time.Sleep(300 * time.Millisecond)
	select {
	case msg := <-caReadChan:
		assert.Fail(t, "Expected no additional messages from server", "got: %+v", msg)
	default:
	}
}

func TestProtocolVersionValidation(t *testing.T) { //nolint:maintidx
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cookie := make([]byte, 20)
	_, err := rand.Read(cookie)
	assert.NoError(t, err)

	var rand [28]byte
	random := handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand}

	config := &Config{
		CipherSuites:   []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		FlightInterval: 100 * time.Millisecond,
	}

	t.Run("Server", func(t *testing.T) {
		serverCases := map[string]struct {
			records []*recordlayer.RecordLayer
		}{
			"ClientHelloVersion": {
				records: []*recordlayer.RecordLayer{
					{
						Header: recordlayer.Header{
							Version: protocol.Version1_2,
						},
						Content: &handshake.Handshake{
							Message: &handshake.MessageClientHello{
								Version:            protocol.Version{Major: 0xfe, Minor: 0xff}, // try to downgrade
								Cookie:             cookie,
								Random:             random,
								CipherSuiteIDs:     []uint16{uint16((&ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}).ID())},
								CompressionMethods: defaultCompressionMethods(),
							},
						},
					},
				},
			},
			"SecondsClientHelloVersion": {
				records: []*recordlayer.RecordLayer{
					{
						Header: recordlayer.Header{
							Version: protocol.Version1_2,
						},
						Content: &handshake.Handshake{
							Message: &handshake.MessageClientHello{
								Version:            protocol.Version1_2,
								Cookie:             cookie,
								Random:             random,
								CipherSuiteIDs:     []uint16{uint16((&ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}).ID())},
								CompressionMethods: defaultCompressionMethods(),
							},
						},
					},
					{
						Header: recordlayer.Header{
							Version:        protocol.Version1_2,
							SequenceNumber: 1,
						},
						Content: &handshake.Handshake{
							Header: handshake.Header{
								MessageSequence: 1,
							},
							Message: &handshake.MessageClientHello{
								Version:            protocol.Version{Major: 0xfe, Minor: 0xff}, // try to downgrade
								Cookie:             cookie,
								Random:             random,
								CipherSuiteIDs:     []uint16{uint16((&ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}).ID())},
								CompressionMethods: defaultCompressionMethods(),
							},
						},
					},
				},
			},
		}
		for name, serverCase := range serverCases {
			serverCase := serverCase
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()
				defer func() {
					assert.NoError(t, ca.Close())
				}()

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				var wg sync.WaitGroup
				wg.Add(1)
				defer wg.Wait()
				go func() {
					defer wg.Done()
					_, err := testServer(
						ctx,
						dtlsnet.PacketConnFromConn(cb),
						cb.RemoteAddr(),
						config,
						true,
					)
					assert.ErrorIs(t, err, errUnsupportedProtocolVersion)
				}()

				time.Sleep(50 * time.Millisecond)

				resp := make([]byte, 1024)
				for _, record := range serverCase.records {
					packet, err := record.Marshal()
					assert.NoError(t, err)

					_, werr := ca.Write(packet)
					assert.NoError(t, werr)

					n, rerr := ca.Read(resp[:cap(resp)])
					assert.NoError(t, rerr)

					resp = resp[:n]
				}

				h := &recordlayer.Header{}
				assert.NoError(t, h.Unmarshal(resp))
				assert.Equal(t, protocol.ContentTypeAlert, h.ContentType, "Peer must return alert to unsupported protocol version")
			})
		}
	})

	t.Run("Client", func(t *testing.T) {
		clientCases := map[string]struct {
			records []*recordlayer.RecordLayer
		}{
			"ServerHelloVersion": {
				records: []*recordlayer.RecordLayer{
					{
						Header: recordlayer.Header{
							Version: protocol.Version1_2,
						},
						Content: &handshake.Handshake{
							Message: &handshake.MessageHelloVerifyRequest{
								Version: protocol.Version1_2,
								Cookie:  cookie,
							},
						},
					},
					{
						Header: recordlayer.Header{
							Version:        protocol.Version1_2,
							SequenceNumber: 1,
						},
						Content: &handshake.Handshake{
							Header: handshake.Header{
								MessageSequence: 1,
							},
							Message: &handshake.MessageServerHello{
								Version: protocol.Version{Major: 0xfe, Minor: 0xff}, // try to downgrade
								Random:  random,
								CipherSuiteID: func() *uint16 {
									id := uint16(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)

									return &id
								}(),
								CompressionMethod: defaultCompressionMethods()[0],
							},
						},
					},
				},
			},
		}
		for name, clientCase := range clientCases {
			clientCase := clientCase
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()
				defer func() {
					assert.NoError(t, ca.Close())
				}()

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				var wg sync.WaitGroup
				wg.Add(1)
				defer wg.Wait()
				go func() {
					defer wg.Done()
					_, err := testClient(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true)
					assert.ErrorIs(t, err, errUnsupportedProtocolVersion)
				}()

				time.Sleep(50 * time.Millisecond)

				for _, record := range clientCase.records {
					_, err := ca.Read(make([]byte, 1024))
					assert.NoError(t, err)

					packet, err := record.Marshal()
					assert.NoError(t, err)

					_, err = ca.Write(packet)
					assert.NoError(t, err)
				}
				resp := make([]byte, 1024)
				n, err := ca.Read(resp)
				assert.NoError(t, err)

				resp = resp[:n]

				h := &recordlayer.Header{}
				assert.NoError(t, h.Unmarshal(resp))
				assert.Equal(t, protocol.ContentTypeAlert, h.ContentType, "Peer must return alert to unsupported protocol version")
			})
		}
	})
}

func TestMultipleHelloVerifyRequest(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cookies := [][]byte{
		// first clientHello contains an empty cookie
		{},
	}
	var packets [][]byte
	for i := 0; i < 2; i++ {
		cookie := make([]byte, 20)
		_, err := rand.Read(cookie)
		assert.NoError(t, err)

		cookies = append(cookies, cookie)

		record := &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				SequenceNumber: uint64(i), //nolint:gosec // G101
				Version:        protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				Header: handshake.Header{
					MessageSequence: uint16(i), //nolint:gosec // G115
				},
				Message: &handshake.MessageHelloVerifyRequest{
					Version: protocol.Version1_2,
					Cookie:  cookie,
				},
			},
		}
		packet, err := record.Marshal()
		assert.NoError(t, err)

		packets = append(packets, packet)
	}

	ca, cb := dpipe.Pipe()
	defer func() {
		assert.NoError(t, ca.Close())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		_, _ = testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{}, false)
	}()

	for i, cookie := range cookies {
		// read client hello
		resp := make([]byte, 1024)
		n, err := cb.Read(resp)
		assert.NoError(t, err)

		record := &recordlayer.RecordLayer{}
		assert.NoError(t, record.Unmarshal(resp[:n]))

		clientHello, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageClientHello)
		assert.True(t, ok)
		assert.Equal(t, cookie, clientHello.Cookie)
		if len(packets) <= i {
			break
		}
		// write hello verify request
		_, err = cb.Write(packets[i])
		assert.NoError(t, err)
	}
	cancel()
}

// Assert that a DTLS Server only responds with RenegotiationInfo if a ClientHello contained that
// extension according to RFC5746 section 3.6, RFC5246 section 7.4.1.4 and RFC5746 section 4.2.
func TestRenegotationInfo(t *testing.T) { //nolint:cyclop
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(10 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	resp := make([]byte, 1024)

	for _, testCase := range []struct {
		Name                    string
		ExpectRenegotiationInfo bool
	}{
		{
			"Include RenegotiationInfo",
			true,
		},
		{
			"No RenegotiationInfo",
			false,
		},
	} {
		test := testCase
		t.Run(test.Name, func(t *testing.T) {
			ca, cb := dpipe.Pipe()
			defer func() {
				assert.NoError(t, ca.Close())
			}()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go func() {
				_, err := testServer(
					ctx,
					dtlsnet.PacketConnFromConn(cb),
					cb.RemoteAddr(),
					&Config{},
					true,
				)
				assert.ErrorIs(t, err, context.Canceled)
			}()

			time.Sleep(50 * time.Millisecond)

			extensions := []extension.Extension{}
			if test.ExpectRenegotiationInfo {
				extensions = append(extensions, &extension.RenegotiationInfo{
					RenegotiatedConnection: 0,
				})
			}
			err := sendClientHello([]byte{}, ca, 0, extensions)
			assert.NoError(t, err)

			n, err := ca.Read(resp)
			assert.NoError(t, err)

			record := &recordlayer.RecordLayer{}
			assert.NoError(t, record.Unmarshal(resp[:n]))

			helloVerifyRequest, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageHelloVerifyRequest)
			assert.True(t, ok)

			err = sendClientHello(helloVerifyRequest.Cookie, ca, 1, extensions)
			assert.NoError(t, err)

			n, err = ca.Read(resp)
			assert.NoError(t, err)

			messages, err := recordlayer.UnpackDatagram(resp[:n])
			assert.NoError(t, err)
			assert.NoError(t, record.Unmarshal(messages[0]))

			serverHello, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageServerHello)
			assert.True(t, ok)

			actualNegotationInfo := false
			for _, v := range serverHello.Extensions {
				if _, ok := v.(*extension.RenegotiationInfo); ok {
					actualNegotationInfo = true
				}
			}

			assert.True(t, test.ExpectRenegotiationInfo == actualNegotationInfo,
				"NegotationInfo state in ServerHello is incorrect: expected(%t) actual(%t)",
				test.ExpectRenegotiationInfo, actualNegotationInfo)
		})
	}
}

func TestServerNameIndicationExtension(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name       string
		ServerName string
		Expected   []byte
		IncludeSNI bool
	}{
		{
			Name:       "Server name is a valid hostname",
			ServerName: "example.com",
			Expected:   []byte("example.com"),
			IncludeSNI: true,
		},
		{
			Name:       "Server name is an IP literal",
			ServerName: "1.2.3.4",
			Expected:   []byte(""),
			IncludeSNI: false,
		},
		{
			Name:       "Server name is empty",
			ServerName: "",
			Expected:   []byte(""),
			IncludeSNI: false,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			go func() {
				conf := &Config{
					ServerName: test.ServerName,
				}

				_, _ = testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), conf, false)
			}()

			// Receive ClientHello
			resp := make([]byte, 1024)
			n, err := cb.Read(resp)
			assert.NoError(t, err)

			r := &recordlayer.RecordLayer{}
			assert.NoError(t, r.Unmarshal(resp[:n]))

			clientHello, ok := r.Content.(*handshake.Handshake).Message.(*handshake.MessageClientHello)
			assert.True(t, ok)

			gotSNI := false
			var actualServerName string
			for _, v := range clientHello.Extensions {
				if _, ok := v.(*extension.ServerName); ok {
					gotSNI = true
					extensionServerName, ok := v.(*extension.ServerName)
					assert.True(t, ok)

					actualServerName = extensionServerName.ServerName
				}
			}

			assert.Equalf(t, test.IncludeSNI, gotSNI, "TestSNI: expected SNI inclusion '%s'", test.Name)
			assert.Equalf(t, test.Expected, []byte(actualServerName), "TestSNI: server name mismatch '%s'", test.Name)
		})
	}
}

func TestALPNExtension(t *testing.T) { //nolint:maintidx
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                   string
		ClientProtocolNameList []string
		ServerProtocolNameList []string
		ExpectedProtocol       string
		ExpectAlertFromClient  bool
		ExpectAlertFromServer  bool
		Alert                  alert.Description
	}{
		{
			Name:                   "Negotiate a protocol",
			ClientProtocolNameList: []string{"http/1.1", "spd/1"},
			ServerProtocolNameList: []string{"spd/1"},
			ExpectedProtocol:       "spd/1",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  false,
			Alert:                  0,
		},
		{
			Name:                   "Server doesn't support any",
			ClientProtocolNameList: []string{"http/1.1", "spd/1"},
			ServerProtocolNameList: []string{},
			ExpectedProtocol:       "",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  false,
			Alert:                  0,
		},
		{
			Name:                   "Negotiate with higher server precedence",
			ClientProtocolNameList: []string{"http/1.1", "spd/1", "http/3"},
			ServerProtocolNameList: []string{"ssh/2", "http/3", "spd/1"},
			ExpectedProtocol:       "http/3",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  false,
			Alert:                  0,
		},
		{
			Name:                   "Empty intersection",
			ClientProtocolNameList: []string{"http/1.1", "http/3"},
			ServerProtocolNameList: []string{"ssh/2", "spd/1"},
			ExpectedProtocol:       "",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  true,
			Alert:                  alert.NoApplicationProtocol,
		},
		{
			Name:                   "Multiple protocols in ServerHello",
			ClientProtocolNameList: []string{"http/1.1"},
			ServerProtocolNameList: []string{"http/1.1"},
			ExpectedProtocol:       "http/1.1",
			ExpectAlertFromClient:  true,
			ExpectAlertFromServer:  false,
			Alert:                  alert.InternalError,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			go func() {
				conf := &Config{
					SupportedProtocols: test.ClientProtocolNameList,
				}
				_, _ = testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), conf, false)
			}()

			// Receive ClientHello
			resp := make([]byte, 1024)
			n, err := cb.Read(resp)
			assert.NoError(t, err)

			ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel2()

			ca2, cb2 := dpipe.Pipe()
			go func() {
				conf := &Config{
					SupportedProtocols: test.ServerProtocolNameList,
				}
				_, err2 := testServer(ctx2, dtlsnet.PacketConnFromConn(cb2), cb2.RemoteAddr(), conf, true)
				if test.ExpectAlertFromServer {
					assert.NotErrorIs(t, err2, context.Canceled)
				}
			}()

			time.Sleep(50 * time.Millisecond)

			// Forward ClientHello
			_, err = ca2.Write(resp[:n])
			assert.NoError(t, err)

			// Receive HelloVerify
			resp2 := make([]byte, 1024)
			n, err = ca2.Read(resp2)
			assert.NoError(t, err)

			// Forward HelloVerify
			_, err = cb.Write(resp2[:n])
			assert.NoError(t, err)

			// Receive ClientHello
			resp3 := make([]byte, 1024)
			n, err = cb.Read(resp3)
			assert.NoError(t, err)

			// Forward ClientHello
			_, err = ca2.Write(resp3[:n])
			assert.NoError(t, err)

			// Receive ServerHello
			resp4 := make([]byte, 1024)
			n, err = ca2.Read(resp4)
			assert.NoError(t, err)

			messages, err := recordlayer.UnpackDatagram(resp4[:n])
			assert.NoError(t, err)

			record := &recordlayer.RecordLayer{}
			assert.NoError(t, record.Unmarshal(messages[0]))

			if test.ExpectAlertFromServer { //nolint:nestif
				a, ok := record.Content.(*alert.Alert)
				assert.True(t, ok)
				assert.Equalf(t, test.Alert, a.Description, "ALPN %v", test.Name)
			} else {
				serverHello, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageServerHello)
				assert.True(t, ok)

				var negotiatedProtocol string
				for _, v := range serverHello.Extensions {
					if _, ok := v.(*extension.ALPN); ok {
						e, ok := v.(*extension.ALPN)
						assert.True(t, ok)

						negotiatedProtocol = e.ProtocolNameList[0]

						// Manipulate ServerHello
						if test.ExpectAlertFromClient {
							e.ProtocolNameList = append(e.ProtocolNameList, "oops")
						}
					}
				}

				assert.Equalf(t, test.ExpectedProtocol, negotiatedProtocol, "ALPN %v", test.Name)

				s, err := record.Marshal()
				assert.NoError(t, err)

				// Forward ServerHello
				_, err = cb.Write(s)
				assert.NoError(t, err)

				if test.ExpectAlertFromClient {
					resp5 := make([]byte, 1024)
					n, err = cb.Read(resp5)
					assert.NoError(t, err)

					r2 := &recordlayer.RecordLayer{}
					assert.NoError(t, r2.Unmarshal(resp5[:n]))

					a, ok := r2.Content.(*alert.Alert)
					assert.True(t, ok)
					assert.Equalf(t, test.Alert, a.Description, "ALPN %v", test.Name)
				}
			}

			time.Sleep(50 * time.Millisecond) // Give some time for returned errors
		})
	}
}

// Make sure the supported_groups extension is not included in the ServerHello.
func TestSupportedGroupsExtension(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	t.Run("ServerHello Supported Groups", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		go func() {
			_, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{}, true)
			assert.ErrorIs(t, err, context.Canceled)
		}()
		extensions := []extension.Extension{
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384},
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}

		time.Sleep(50 * time.Millisecond)

		resp := make([]byte, 1024)
		err := sendClientHello([]byte{}, ca, 0, extensions)
		assert.NoError(t, err)

		// Receive ServerHello
		n, err := ca.Read(resp)
		assert.NoError(t, err)

		record := &recordlayer.RecordLayer{}
		assert.NoError(t, record.Unmarshal(resp[:n]))

		helloVerifyRequest, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageHelloVerifyRequest)
		assert.True(t, ok, "Failed to cast MessageHelloVerifyRequest")

		err = sendClientHello(helloVerifyRequest.Cookie, ca, 1, extensions)
		assert.NoError(t, err)

		n, err = ca.Read(resp)
		assert.NoError(t, err)

		messages, err := recordlayer.UnpackDatagram(resp[:n])
		assert.NoError(t, err)
		assert.NoError(t, record.Unmarshal(messages[0]))

		serverHello, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageServerHello)
		assert.True(t, ok, "TestSupportedGroups: Failed to cast MessageServerHello")

		gotGroups := false
		for _, v := range serverHello.Extensions {
			if _, ok := v.(*extension.SupportedEllipticCurves); ok {
				gotGroups = true
			}
		}

		assert.False(t, gotGroups, "TestSupportedGroups: supported_groups extension was sent in ServerHello")
	})
}

func TestSessionResume(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	t.Run("resumed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		type result struct {
			c   *Conn
			err error
		}
		clientRes := make(chan result, 1)

		ss := &memSessStore{}

		id, _ := hex.DecodeString("9b9fc92255634d9fb109febed42166717bb8ded8c738ba71bc7f2a0d9dae0306")
		secret, _ := hex.DecodeString(
			"2e942a37aca5241deb2295b5fcedac221c7078d2503d2b62aeb48c880d7da73c001238b708559686b9da6e829c05ead7",
		)

		s := Session{ID: id, Secret: secret}

		ca, cb := dpipe.Pipe()

		_ = ss.Set(id, s)
		_ = ss.Set([]byte(ca.RemoteAddr().String()+"_example.com"), s)

		go func() {
			config := &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				ServerName:   "example.com",
				SessionStore: ss,
				MTU:          100,
			}
			c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), config, false)
			clientRes <- result{c, err}
		}()

		config := &Config{
			CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerName:   "example.com",
			SessionStore: ss,
			MTU:          100,
		}
		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true)
		assert.NoError(t, err)

		state, ok := server.ConnectionState()
		assert.True(t, ok)

		actualSessionID := state.SessionID
		actualMasterSecret := state.masterSecret
		assert.Equal(t, actualSessionID, id, "TestSessionResumetion SessionID mismatch")
		assert.Equal(t, actualMasterSecret, secret, "TestSessionResumetion masterSecret mismatch")

		defer func() {
			assert.NoError(t, server.Close())
		}()

		res := <-clientRes
		assert.NoError(t, res.err)
		assert.NoError(t, res.c.Close())
	})

	t.Run("new session", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		type result struct {
			c   *Conn
			err error
		}
		clientRes := make(chan result, 1)

		s1 := &memSessStore{}
		s2 := &memSessStore{}

		ca, cb := dpipe.Pipe()
		go func() {
			config := &Config{
				ServerName:   "example.com",
				SessionStore: s1,
			}
			c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), config, false)
			clientRes <- result{c, err}
		}()

		config := &Config{
			SessionStore: s2,
		}
		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true)
		assert.NoError(t, err)

		state, ok := server.ConnectionState()
		assert.True(t, ok)
		actualSessionID := state.SessionID
		actualMasterSecret := state.masterSecret
		ss, _ := s2.Get(actualSessionID)
		assert.Equal(t, actualMasterSecret, ss.Secret, "TestSessionResumetion masterSecret mismatch")

		defer func() {
			assert.NoError(t, server.Close())
		}()

		res := <-clientRes
		assert.NoError(t, res.err)

		cs, _ := s1.Get([]byte(ca.RemoteAddr().String() + "_example.com"))
		assert.Equal(t, actualMasterSecret, cs.Secret, "TestSessionResumetion mismatch")
		assert.NoError(t, res.c.Close())
	})
}

type memSessStore struct {
	sync.Map
}

func (ms *memSessStore) Set(key []byte, s Session) error {
	k := hex.EncodeToString(key)
	ms.Store(k, s)

	return nil
}

func (ms *memSessStore) Get(key []byte) (Session, error) {
	k := hex.EncodeToString(key)

	v, ok := ms.Load(k)
	if !ok {
		return Session{}, nil
	}

	s, ok := v.(Session)
	if !ok {
		return Session{}, nil
	}

	return s, nil
}

func (ms *memSessStore) Del(key []byte) error {
	k := hex.EncodeToString(key)
	ms.Delete(k)

	return nil
}

// Assert that the server only uses CipherSuites with a hash+signature that matches
// the certificate. As specified in rfc5246#section-7.4.3
// .
func TestCipherSuiteMatchesCertificateType(t *testing.T) { //nolint:cyclop
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name           string
		cipherList     []CipherSuiteID
		expectedCipher CipherSuiteID
		generateRSA    bool
	}{
		{
			Name:           "ECDSA Certificate with RSA CipherSuite first",
			cipherList:     []CipherSuiteID{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			expectedCipher: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		{
			Name:           "RSA Certificate with ECDSA CipherSuite first",
			cipherList:     []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			expectedCipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			generateRSA:    true,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			clientErr := make(chan error, 1)
			client := make(chan *Conn, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				c, err := testClient(context.TODO(), dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
					CipherSuites: test.cipherList,
				}, false)
				clientErr <- err
				client <- c
			}()

			var (
				signer crypto.Signer
				err    error
			)

			if test.generateRSA {
				signer, err = rsa.GenerateKey(rand.Reader, 2048)
				assert.NoError(t, err)
			} else {
				signer, err = ecdsa.GenerateKey(cryptoElliptic.P256(), rand.Reader)
				assert.NoError(t, err)
			}

			serverCert, err := selfsign.SelfSign(signer)
			assert.NoError(t, err)

			s, err := testServer(context.TODO(), dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
				CipherSuites: test.cipherList,
				Certificates: []tls.Certificate{serverCert},
			}, false)
			assert.NoError(t, err)
			assert.NoError(t, s.Close())

			c := <-client
			assert.NoError(t, <-clientErr)
			assert.NoError(t, c.Close())

			state, ok := c.ConnectionState()
			assert.True(t, ok)
			assert.Equal(t, test.expectedCipher, state.cipherSuite.ID())
		})
	}
}

// Test that we return the proper certificate if we are serving multiple ServerNames on a single Server.
func TestMultipleServerCertificates(t *testing.T) {
	fooCert, err := selfsign.GenerateSelfSignedWithDNS("foo")
	assert.NoError(t, err)

	barCert, err := selfsign.GenerateSelfSignedWithDNS("bar")
	assert.NoError(t, err)

	caPool := x509.NewCertPool()
	for _, cert := range []tls.Certificate{fooCert, barCert} {
		certificate, err := x509.ParseCertificate(cert.Certificate[0])
		assert.NoError(t, err)
		caPool.AddCert(certificate)
	}

	for _, test := range []struct {
		RequestServerName string
		ExpectedDNSName   string
	}{
		{
			"foo",
			"foo",
		},
		{
			"bar",
			"bar",
		},
		{
			"invalid",
			"foo",
		},
	} {
		test := test
		t.Run(test.RequestServerName, func(t *testing.T) {
			clientErr := make(chan error, 2)
			client := make(chan *Conn, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				clientConn, err := testClient(context.TODO(), dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
					RootCAs:    caPool,
					ServerName: test.RequestServerName,
					VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
						certificate, err := x509.ParseCertificate(rawCerts[0])
						if err != nil {
							return err
						}

						if certificate.DNSNames[0] != test.ExpectedDNSName {
							return errWrongCert
						}

						return nil
					},
				}, false)
				clientErr <- err
				client <- clientConn
			}()

			s, err := testServer(context.TODO(), dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
				Certificates: []tls.Certificate{fooCert, barCert},
			}, false)
			assert.NoError(t, err)
			assert.NoError(t, s.Close())
			assert.NoError(t, <-clientErr)
			assert.NoError(t, (<-client).Close())
		})
	}
}

func TestEllipticCurveConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name            string
		ConfigCurves    []elliptic.Curve
		HandshakeCurves []elliptic.Curve
	}{
		{
			Name:            "Curve defaulting",
			ConfigCurves:    nil,
			HandshakeCurves: defaultCurves,
		},
		{
			Name:            "Single curve",
			ConfigCurves:    []elliptic.Curve{elliptic.X25519},
			HandshakeCurves: []elliptic.Curve{elliptic.X25519},
		},
		{
			Name:            "Multiple curves",
			ConfigCurves:    []elliptic.Curve{elliptic.P384, elliptic.X25519},
			HandshakeCurves: []elliptic.Curve{elliptic.P384, elliptic.X25519},
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		type result struct {
			c   *Conn
			err error
		}
		resultCh := make(chan result)

		go func() {
			client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
				CipherSuites:   []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				EllipticCurves: test.ConfigCurves,
			}, true)
			resultCh <- result{client, err}
		}()

		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
			CipherSuites:   []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			EllipticCurves: test.ConfigCurves,
		}, true)
		assert.NoError(t, err)

		ok := len(test.ConfigCurves) == 0 || len(test.ConfigCurves) == len(test.HandshakeCurves)
		assert.True(t, ok, "Failed to default Elliptic curves")

		if len(test.ConfigCurves) != 0 {
			assert.Equal(t, len(test.HandshakeCurves), len(server.fsm.cfg.ellipticCurves), "Failed to configure Elliptic curves")

			for i, c := range test.ConfigCurves {
				assert.Equal(t, c, server.fsm.cfg.ellipticCurves[i], "Failed to maintain Elliptic curve order")
			}
		}

		res := <-resultCh
		assert.NoError(t, res.err, "Client error")

		defer func() {
			assert.NoError(t, server.Close())
			assert.NoError(t, res.c.Close())
		}()
	}
}

func TestSkipHelloVerify(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := dpipe.Pipe()
	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	gotHello := make(chan struct{})

	go func() {
		server, sErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
			Certificates:            []tls.Certificate{certificate},
			LoggerFactory:           logging.NewDefaultLoggerFactory(),
			InsecureSkipVerifyHello: true,
		}, false)
		assert.NoError(t, sErr)

		buf := make([]byte, 1024)
		_, sErr = server.Read(buf) //nolint:contextcheck
		assert.NoError(t, sErr)
		gotHello <- struct{}{}
		assert.NoError(t, server.Close()) //nolint:contextcheck
	}()

	client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
		LoggerFactory:      logging.NewDefaultLoggerFactory(),
		InsecureSkipVerify: true,
	}, false)
	assert.NoError(t, err)

	_, err = client.Write([]byte("hello"))
	assert.NoError(t, err)

	select {
	case <-gotHello:
		// OK
	case <-time.After(time.Second * 5):
		assert.Fail(t, "timeout")
	}
	assert.NoError(t, client.Close())
}

type connWithCallback struct {
	net.Conn
	onWrite func([]byte)
}

func (c *connWithCallback) Write(b []byte) (int, error) {
	if c.onWrite != nil {
		c.onWrite(b)
	}

	return c.Conn.Write(b)
}

func TestApplicationDataQueueLimited(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := dpipe.Pipe()
	defer func() {
		assert.NoError(t, ca.Close())
	}()
	defer func() {
		assert.NoError(t, cb.Close())
	}()

	done := make(chan struct{})
	go func() {
		serverCert, err := selfsign.GenerateSelfSigned()
		assert.NoError(t, err)

		cfg := &Config{}
		cfg.Certificates = []tls.Certificate{serverCert}

		dconn, err := createConn(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), cfg, false, nil)
		assert.NoError(t, err)

		go func() {
			for i := 0; i < 5; i++ {
				dconn.lock.RLock()
				qlen := len(dconn.encryptedPackets)
				dconn.lock.RUnlock()
				assert.GreaterOrEqual(t, maxAppDataPacketQueueSize, qlen, "too many encrypted packets enqueued")
				time.Sleep(1 * time.Second)
			}
		}()
		assert.Error(t, dconn.HandshakeContext(ctx))
		close(done)
	}()
	extensions := []extension.Extension{}

	time.Sleep(50 * time.Millisecond)

	assert.NoError(t, sendClientHello([]byte{}, ca, 0, extensions))

	time.Sleep(50 * time.Millisecond)

	for i := 0; i < 1000; i++ {
		// Send an application data packet
		packet, err := (&recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version:        protocol.Version1_2,
				SequenceNumber: uint64(3),
				Epoch:          1, // use an epoch greater than 0
			},
			Content: &protocol.ApplicationData{
				Data: []byte{1, 2, 3, 4},
			},
		}).Marshal()
		assert.NoError(t, err)
		_, err = ca.Write(packet)
		assert.NoError(t, err)
		if i%100 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	time.Sleep(1 * time.Second)
	assert.NoError(t, ca.Close())
	<-done
}

func TestHelloRandom(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := dpipe.Pipe()
	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	gotHello := make(chan struct{})

	chRandom := [handshake.RandomBytesLength]byte{}
	_, err = rand.Read(chRandom[:])
	assert.NoError(t, err)

	go func() {
		server, sErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
			GetCertificate: func(chi *ClientHelloInfo) (*tls.Certificate, error) {
				if len(chi.CipherSuites) == 0 {
					return &certificate, nil
				}
				assert.Equal(t, chRandom[:], chi.RandomBytes[:])

				return &certificate, nil
			},
			LoggerFactory: logging.NewDefaultLoggerFactory(),
		}, false)
		assert.NoError(t, sErr)

		buf := make([]byte, 1024)
		_, sErr = server.Read(buf) //nolint:contextcheck
		assert.NoError(t, sErr)

		gotHello <- struct{}{}
		assert.NoError(t, server.Close()) //nolint:contextcheck
	}()

	client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
		LoggerFactory: logging.NewDefaultLoggerFactory(),
		HelloRandomBytesGenerator: func() [handshake.RandomBytesLength]byte {
			return chRandom
		},
		InsecureSkipVerify: true,
	}, false)
	assert.NoError(t, err)

	_, err = client.Write([]byte("hello"))
	assert.NoError(t, err)

	select {
	case <-gotHello:
		// OK
	case <-time.After(time.Second * 5):
		assert.Fail(t, "timeout")
	}

	assert.NoError(t, client.Close())
}

func TestOnConnectionAttempt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*20)
	defer cancel()

	var clientOnConnectionAttempt, serverOnConnectionAttempt atomic.Int32

	ca, cb := dpipe.Pipe()
	clientErr := make(chan error, 1)
	go func() {
		_, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
			OnConnectionAttempt: func(in net.Addr) error {
				clientOnConnectionAttempt.Store(1)
				assert.NotNil(t, in)

				return nil
			},
		}, true)
		clientErr <- err
	}()

	expectedErr := &FatalError{}
	_, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
		OnConnectionAttempt: func(in net.Addr) error {
			serverOnConnectionAttempt.Store(1)
			assert.NotNil(t, in)

			return expectedErr
		},
	}, true)
	assert.ErrorIs(t, err, expectedErr)
	assert.Error(t, <-clientErr)
	assert.Equal(t, int32(1), serverOnConnectionAttempt.Load(), "OnConnectionAttempt did not fire for server")
	assert.Equal(t, int32(0), clientOnConnectionAttempt.Load(), "OnConnectionAttempt fired for client")
}

func TestFragmentBuffer_Retransmission(t *testing.T) {
	fragmentBuffer := newFragmentBuffer()
	frag := []byte{
		0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x30, 0x03, 0x00,
		0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff, 0x01, 0x01,
	}

	_, isRetransmission, err := fragmentBuffer.push(frag)
	assert.NoError(t, err)
	assert.False(t, isRetransmission)

	v, _ := fragmentBuffer.pop()
	assert.NotNil(t, v)

	_, isRetransmission, err = fragmentBuffer.push(frag)
	assert.NoError(t, err)
	assert.True(t, isRetransmission)
}

func TestConnectionState(t *testing.T) {
	ca, cb := dpipe.Pipe()

	// Setup client
	clientCfg := &Config{}
	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	clientCfg.Certificates = []tls.Certificate{clientCert}
	clientCfg.InsecureSkipVerify = true
	client, err := Client(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), clientCfg)
	assert.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	_, ok := client.ConnectionState()
	assert.False(t, ok)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errorChannel := make(chan error)
	go func() {
		errC := client.HandshakeContext(ctx)
		errorChannel <- errC
	}()

	// Setup server
	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{}, true)
	assert.NoError(t, err)

	defer func() {
		_ = server.Close()
	}()

	err = <-errorChannel
	assert.NoError(t, err)

	_, ok = client.ConnectionState()
	assert.True(t, ok)
}

func TestMultiHandshake(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	ca, cb := dpipe.Pipe()
	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	server, err := Server(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
		Certificates: []tls.Certificate{serverCert},
	})
	assert.NoError(t, err)

	go func() {
		_ = server.Handshake()
	}()

	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	client, err := Client(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
		Certificates: []tls.Certificate{clientCert},
	})
	assert.NoError(t, err)
	assert.Error(t, client.Handshake())
	assert.Error(t, client.Handshake())
	assert.NoError(t, server.Close())
	assert.NoError(t, client.Close())
}

func TestCloseDuringHandshake(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	for i := 0; i < 100; i++ {
		_, cb := dpipe.Pipe()
		server, err := Server(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
			Certificates: []tls.Certificate{serverCert},
		})
		assert.NoError(t, err)

		waitChan := make(chan struct{})
		go func() {
			close(waitChan)
			_ = server.Handshake()
		}()

		<-waitChan
		assert.NoError(t, server.Close())
	}
}

func TestCloseWithoutHandshake(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	_, cb := dpipe.Pipe()
	server, err := Server(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
		Certificates: []tls.Certificate{serverCert},
	})
	assert.NoError(t, err)
	assert.NoError(t, server.Close())
}
