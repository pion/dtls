// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
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
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
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
	"github.com/pion/transport/v4/dpipe"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
)

var (
	errTestPSKInvalidIdentity       = errors.New("TestPSK: Server got invalid identity")
	errTestPSKClientInvalidIdentity = errors.New("TestPSK: Client got invalid identity")
	errPSKRejected                  = errors.New("psk Rejected")
	errNotExpectedChain             = errors.New("not expected chain")
	errExpecedChain                 = errors.New("expected chain")
	errWrongCert                    = errors.New("wrong cert")
	errConnectionAttemptFailed      = errors.New("connection attempt failed")
)

const renegotiationInfoSCSV uint16 = 0x00ff

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

		atomic.StoreUint64(&ca.state.LocalSequenceNumber[1], recordlayer.MaxSequenceNumber)
		_, werr := ca.Write(make([]byte, 100))
		assert.NoError(t, werr, "Write must send message with maximum sequence number")
		_, werr = ca.Write(make([]byte, 100))
		assert.ErrorIs(t, werr, dtlserrors.ErrSequenceNumberOverflow, "Write must abandonsend message with maximum sequence number") //nolint:lll

		assert.NoError(t, ca.Close())
		assert.NoError(t, cb.Close())
	})
	t.Run("Handshake", func(t *testing.T) {
		ca, cb, err := pipeMemory()
		assert.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		atomic.StoreUint64(&ca.state.LocalSequenceNumber[0], recordlayer.MaxSequenceNumber+1)

		// Try to send handshake packet.
		werr := ca.writePackets(ctx, []*dtlsflight.Packet{
			{
				Record: &recordlayer.RecordLayer{
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
		assert.ErrorIs(t, werr, dtlserrors.ErrSequenceNumberOverflow,
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

	resultCh := make(chan result, 1) // Buffered to prevent goroutine leak
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Setup client
	go func() {
		client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), []ClientOption{
			WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80),
		}, true)
		resultCh <- result{client, err}
	}()

	// Setup server
	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), []ServerOption{
		WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80),
	}, true)
	if err != nil {
		// Read from resultCh to prevent goroutine leak
		if res := <-resultCh; res.c != nil {
			_ = res.c.Close()
		}

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
	opts []ClientOption,
	generateCertificate bool,
) (*Conn, error) {
	if generateCertificate {
		clientCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		opts = append(opts, WithCertificates(clientCert))
	}
	opts = append(opts, WithInsecureSkipVerify(true))
	conn, err := ClientWithOptions(pktConn, rAddr, opts...)
	if err != nil {
		return nil, err
	}

	return conn, conn.HandshakeContext(ctx)
}

func testServer(
	ctx context.Context,
	c net.PacketConn,
	rAddr net.Addr,
	opts []ServerOption,
	generateCertificate bool,
) (*Conn, error) {
	if generateCertificate {
		serverCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		opts = append(opts, WithCertificates(serverCert))
	}
	conn, err := ServerWithOptions(c, rAddr, opts...)
	if err != nil {
		return nil, err
	}

	return conn, conn.HandshakeContext(ctx)
}

func sendClientHello(
	cookie []byte,
	ca net.Conn,
	sequenceNumber uint64,
	extensions []extension.Extension,
	cipherSuiteIDsOverride ...uint16,
) error {
	cipherSuites := cipherSuiteIDsOverride
	if len(cipherSuites) == 0 {
		cipherSuites = cipherSuiteIDs(defaultCipherSuites())
	}

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
				CipherSuiteIDs:     cipherSuites,
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
		serverOpts []ServerOption
		clientOpts []ClientOption
		errServer  error
		errClient  error
	}{
		"CipherSuiteNoIntersection": {
			serverOpts: []ServerOption{
				WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			},
			clientOpts: []ClientOption{
				WithCipherSuites(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
			},
			errServer: dtlserrors.ErrCipherSuiteNoIntersection,
			errClient: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
		},
		"SignatureSchemesNoIntersection": {
			serverOpts: []ServerOption{
				WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				WithSignatureSchemes(tls.ECDSAWithP256AndSHA256),
			},
			clientOpts: []ClientOption{
				WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				WithSignatureSchemes(tls.ECDSAWithP521AndSHA512),
			},
			errServer: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			errClient: dtlserrors.ErrNoAvailableSignatureSchemes,
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			clientErr := make(chan error, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				_, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), testCase.clientOpts, true)
				clientErr <- err
			}()

			_, errServer := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), testCase.serverOpts, true)
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
			[]ClientOption{WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)},
			true,
		)
		clientErr <- result{client, err}
	}()

	server, errServer := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), []ServerOption{
		WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
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
		state: dtlsstate.State{
			LocalRandom:         handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand},
			RemoteRandom:        handshake.Random{GMTUnixTime: time.Unix(1000, 0), RandomBytes: rand},
			LocalSequenceNumber: []uint64{0, 0},
			CipherSuite:         &ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{},
		},
	}
	conn.setLocalEpoch(0)
	conn.setRemoteEpoch(0)

	state, ok := conn.ConnectionState()
	assert.True(t, ok)

	_, err := state.ExportKeyingMaterial(exportLabel, nil, 0)
	assert.ErrorIs(t, err, dtlserrors.ErrHandshakeInProgress, "ExportKeyingMaterial when epoch == 0 error mismatch")

	conn.setLocalEpoch(1)
	state, ok = conn.ConnectionState()
	assert.True(t, ok)

	_, err = state.ExportKeyingMaterial(exportLabel, []byte{0x00}, 0)
	assert.ErrorIs(t, err, dtlserrors.ErrContextUnsupported, "ExportKeyingMaterial with context mismatch")

	for k := range invalidKeyingLabels() {
		state, ok = conn.ConnectionState()
		assert.True(t, ok)

		_, err = state.ExportKeyingMaterial(k, nil, 0)
		assert.ErrorIs(t, err, dtlserrors.ErrReservedExportKeyingMaterial, "ExportKeyingMaterial reserved label mismatch")
	}

	state, ok = conn.ConnectionState()
	assert.True(t, ok)

	keyingMaterial, err := state.ExportKeyingMaterial(exportLabel, nil, 10)
	assert.NoError(t, err, "ExportingKeyingMaterial as server error")
	assert.Equal(t, expectedServerKey, keyingMaterial, "ExportKeyingMaterial client export mismatch")

	conn.state.IsClient = true
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
		cipherSuites           []CipherSuiteID
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
			cipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		},
		{
			Name:           "Server identity specified - Server verify connection fails",
			ServerIdentity: []byte("Test Identity"),
			ClientIdentity: []byte("Client Identity"),
			cipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
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
			cipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
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
			cipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		},
		{
			Name:           "TLS_PSK_WITH_AES_128_CBC_SHA256",
			ServerIdentity: nil,
			ClientIdentity: []byte("Client Identity"),
			cipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CBC_SHA256},
		},
		{
			Name:           "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
			ServerIdentity: nil,
			ClientIdentity: []byte("Client Identity"),
			cipherSuites:   []CipherSuiteID{TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256},
		},
		{
			Name:           "Client identity empty",
			ServerIdentity: nil,
			ClientIdentity: []byte{},
			cipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
		},
	} {
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
				clientOpts := []ClientOption{
					WithPSK(func(hint []byte) ([]byte, error) {
						if !bytes.Equal(test.ServerIdentity, hint) {
							return nil, fmt.Errorf(
								"%w expected(% 02x) actual(% 02x)",
								errTestPSKClientInvalidIdentity,
								test.ServerIdentity, hint,
							)
						}

						return []byte{0xAB, 0xC1, 0x23}, nil
					}),
					WithPSKIdentityHint(test.ClientIdentity),
					WithCipherSuites(test.cipherSuites...),
				}
				if test.ClientVerifyConnection != nil {
					clientOpts = append(clientOpts, WithVerifyConnection(test.ClientVerifyConnection))
				}

				c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), clientOpts, false)
				clientRes <- result{c, err}
			}()

			serverOpts := []ServerOption{
				WithPSK(func(hint []byte) ([]byte, error) {
					t.Log(hint)
					if !bytes.Equal(test.ClientIdentity, hint) {
						return nil, fmt.Errorf("%w: expected(% 02x) actual(% 02x)", errTestPSKInvalidIdentity, test.ClientIdentity, hint)
					}

					return []byte{0xAB, 0xC1, 0x23}, nil
				}),
				WithCipherSuites(test.cipherSuites...),
			}
			if test.ServerIdentity != nil {
				serverOpts = append(serverOpts, WithPSKIdentityHint(test.ServerIdentity))
			}
			if test.ServerVerifyConnection != nil {
				serverOpts = append(serverOpts, WithVerifyConnection(test.ServerVerifyConnection))
			}

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), serverOpts, false)
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
		opts := []ClientOption{
			WithPSK(func([]byte) ([]byte, error) {
				return nil, pskRejected
			}),
			WithPSKIdentityHint([]byte{}),
			WithCipherSuites(TLS_PSK_WITH_AES_128_CCM_8),
		}

		_, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts, false)
		clientErr <- err
	}()

	opts := []ServerOption{
		WithPSK(func([]byte) ([]byte, error) {
			return nil, pskRejected
		}),
		WithPSKIdentityHint([]byte{}),
		WithCipherSuites(TLS_PSK_WITH_AES_128_CCM_8),
	}

	_, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), opts, false)
	assert.ErrorIs(t, err, serverAlertError, "TestPSK: Server should fail with alert error")
	assert.ErrorIs(t, <-clientErr, pskRejected, "TestPSK: Client should fail with pskRejected error")
}

func TestPSKMismatchNoRetransmitLoop(t *testing.T) {
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var serverWrites atomic.Int32
	var clientWrites atomic.Int32

	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
	}()
	defer func() {
		_ = cb.Close()
	}()

	caCount := &connWithCallback{Conn: ca}
	caCount.onWrite = func([]byte) {
		clientWrites.Add(1)
	}
	cbCount := &connWithCallback{Conn: cb}
	cbCount.onWrite = func([]byte) {
		serverWrites.Add(1)
	}

	clientErr := make(chan error, 1)
	serverErr := make(chan error, 1)

	go func() {
		opts := []ClientOption{
			WithPSK(func([]byte) ([]byte, error) {
				return []byte("client-psk"), nil
			}),
			WithPSKIdentityHint([]byte("Client Identity")),
			WithCipherSuites(TLS_PSK_WITH_AES_128_CCM_8),
		}

		c, err := testClient(ctx, dtlsnet.PacketConnFromConn(caCount), caCount.RemoteAddr(), opts, false)
		if c != nil {
			_ = c.Close() //nolint:contextcheck
		}
		clientErr <- err
	}()

	go func() {
		opts := []ServerOption{
			WithPSK(func([]byte) ([]byte, error) {
				return []byte("server-psk"), nil
			}),
			WithCipherSuites(TLS_PSK_WITH_AES_128_CCM_8),
		}

		s, err := testServer(ctx, dtlsnet.PacketConnFromConn(cbCount), cbCount.RemoteAddr(), opts, false)
		if s != nil {
			_ = s.Close() //nolint:contextcheck
		}
		serverErr <- err
	}()

	serverErrRes := <-serverErr
	clientErrRes := <-clientErr

	assert.ErrorContains(t, serverErrRes, "handshake failed")
	assert.ErrorContains(t, clientErrRes, "handshake failed")

	serverCount := serverWrites.Load()
	clientCount := clientWrites.Load()

	time.Sleep(2 * time.Second)

	assert.Equal(t, serverCount, serverWrites.Load(), "Server should not retransmit after handshake failure")
	assert.Equal(t, clientCount, clientWrites.Load(), "Client should not retransmit after handshake failure")
	assert.LessOrEqual(t, serverCount, int32(20), "Server retransmit count too high for backoff")
	assert.LessOrEqual(t, clientCount, int32(20), "Client retransmit count too high for backoff")
}

// Assert that ServerKeyExchange is only sent if Identity is set on server side.
func TestPSKServerKeyExchange(t *testing.T) { //nolint:cyclop
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
		testCase := test
		t.Run(testCase.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var gotServerKeyExchange atomic.Bool
			expectedServerKeyExchange := testCase.SetIdentity

			clientErr := make(chan error, 1)
			ca, cb := dpipe.Pipe()
			cbAnalyzer := &connWithCallback{Conn: cb}
			cbAnalyzer.onWrite = func(in []byte) {
				messages, err := recordlayer.UnpackDatagram(in)
				assert.NoError(t, err)

				for i := range messages {
					var header recordlayer.Header
					if err := header.Unmarshal(messages[i]); err != nil {
						continue
					}
					if header.ContentType != protocol.ContentTypeHandshake || header.Epoch != 0 {
						continue
					}
					payload := messages[i][recordlayer.FixedHeaderSize:]
					for len(payload) >= handshake.HeaderLength {
						var h handshake.Header
						if err := h.Unmarshal(payload); err != nil {
							break
						}
						if h.Type == handshake.TypeServerKeyExchange {
							gotServerKeyExchange.Store(true)

							break
						}
						fragLen := int(h.FragmentLength)
						if fragLen <= 0 || handshake.HeaderLength+fragLen > len(payload) {
							break
						}
						payload = payload[handshake.HeaderLength+fragLen:]
					}
				}
			}

			go func() {
				opts := []ClientOption{
					WithPSK(func([]byte) ([]byte, error) {
						return []byte{0xAB, 0xC1, 0x23}, nil
					}),
					WithPSKIdentityHint([]byte{0xAB, 0xC1, 0x23}),
					WithCipherSuites(TLS_PSK_WITH_AES_128_CCM_8),
				}

				if client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts, false); err != nil {
					clientErr <- err
				} else {
					clientErr <- client.Close() //nolint
				}
			}()

			opts := []ServerOption{
				WithPSK(func([]byte) ([]byte, error) {
					return []byte{0xAB, 0xC1, 0x23}, nil
				}),
				WithCipherSuites(TLS_PSK_WITH_AES_128_CCM_8),
			}
			if testCase.SetIdentity {
				opts = append(opts, WithPSKIdentityHint([]byte{0xAB, 0xC1, 0x23}))
			}

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cbAnalyzer), cbAnalyzer.RemoteAddr(), opts, false)
			assert.NoError(t, err)

			// Read the value immediately after handshake completes, before closing
			receivedServerKeyExchange := gotServerKeyExchange.Load()

			assert.NoError(t, server.Close())
			if err := <-clientErr; err != nil {
				assert.ErrorIs(t, err, &alertError{&alert.Alert{Level: alert.Warning, Description: alert.CloseNotify}},
					"TestPSK: Client error")
			}

			assert.Equal(t, expectedServerKeyExchange, receivedServerKeyExchange)
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
		c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), nil, true)
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
			WantServerError: dtlserrors.ErrServerNoMatchingSRTPProfile,
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
			Name:            "Multiple Suites, Server Chooses",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AES128_CM_HMAC_SHA1_32},
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_32, SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile: SRTP_AES128_CM_HMAC_SHA1_32,
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
			opts := []ClientOption{WithSRTPMasterKeyIdentifier(test.ServerSRTPMasterKeyIdentifier)}
			if len(test.ClientSRTP) > 0 {
				opts = append(opts, WithSRTPProtectionProfiles(test.ClientSRTP...))
			}
			client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts, true)
			resultCh <- result{client, err}
		}()

		opts := []ServerOption{WithSRTPMasterKeyIdentifier(test.ClientSRTPMasterKeyIdentifier)}
		if len(test.ServerSRTP) > 0 {
			opts = append(opts, WithSRTPProtectionProfiles(test.ServerSRTP...))
		}
		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), opts, true)
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
			clientOpts         []ClientOption
			serverOpts         []ServerOption
			clientAuth         ClientAuthType
			expectedClientCert [][]byte
			expectedServerCert [][]byte
			wantErr            bool
		}{
			"NoClientCert": {
				clientOpts:         []ClientOption{WithRootCAs(srvCAPool)},
				serverOpts:         []ServerOption{WithCertificates(srvCert), WithClientAuth(NoClientCert), WithClientCAs(caPool)},
				clientAuth:         NoClientCert,
				expectedServerCert: srvCert.Certificate,
			},
			"NoClientCert_ServerVerifyConnectionFails": {
				clientOpts: []ClientOption{WithRootCAs(srvCAPool)},
				serverOpts: []ServerOption{
					WithCertificates(srvCert),
					WithClientAuth(NoClientCert),
					WithClientCAs(caPool),
					WithVerifyConnection(func(*State) error {
						return errExample
					}),
				},
				clientAuth:         NoClientCert,
				expectedServerCert: srvCert.Certificate,
				wantErr:            true,
			},
			"NoClientCert_ClientVerifyConnectionFails": {
				clientOpts: []ClientOption{
					WithRootCAs(srvCAPool),
					WithVerifyConnection(func(*State) error {
						return errExample
					}),
				},
				serverOpts:         []ServerOption{WithCertificates(srvCert), WithClientAuth(NoClientCert), WithClientCAs(caPool)},
				clientAuth:         NoClientCert,
				expectedServerCert: srvCert.Certificate,
				wantErr:            true,
			},
			"NoClientCert_cert": {
				clientOpts:         []ClientOption{WithRootCAs(srvCAPool), WithCertificates(cert)},
				serverOpts:         []ServerOption{WithCertificates(srvCert), WithClientAuth(RequireAnyClientCert)},
				clientAuth:         RequireAnyClientCert,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
			"RequestClientCert_cert_sigscheme": { // specify signature algorithm
				clientOpts: []ClientOption{WithRootCAs(srvCAPool), WithCertificates(cert)},
				serverOpts: []ServerOption{
					WithSignatureSchemes(tls.ECDSAWithP521AndSHA512),
					WithCertificates(srvCert),
					WithClientAuth(RequestClientCert),
				},
				clientAuth:         RequestClientCert,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
			"RequestClientCert_cert": {
				clientOpts:         []ClientOption{WithRootCAs(srvCAPool), WithCertificates(cert)},
				serverOpts:         []ServerOption{WithCertificates(srvCert), WithClientAuth(RequestClientCert)},
				clientAuth:         RequestClientCert,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
			"RequestClientCert_no_cert": {
				clientOpts: []ClientOption{WithRootCAs(srvCAPool)},
				serverOpts: []ServerOption{
					WithCertificates(srvCert),
					WithClientAuth(RequestClientCert),
					WithClientCAs(caPool),
				},
				clientAuth:         RequestClientCert,
				expectedServerCert: srvCert.Certificate,
			},
			"RequireAnyClientCert": {
				clientOpts:         []ClientOption{WithRootCAs(srvCAPool), WithCertificates(cert)},
				serverOpts:         []ServerOption{WithCertificates(srvCert), WithClientAuth(RequireAnyClientCert)},
				clientAuth:         RequireAnyClientCert,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
			"RequireAnyClientCert_error": {
				clientOpts:         []ClientOption{WithRootCAs(srvCAPool)},
				serverOpts:         []ServerOption{WithCertificates(srvCert), WithClientAuth(RequireAnyClientCert)},
				clientAuth:         RequireAnyClientCert,
				expectedServerCert: srvCert.Certificate,
				wantErr:            true,
			},
			"VerifyClientCertIfGiven_no_cert": {
				clientOpts: []ClientOption{WithRootCAs(srvCAPool)},
				serverOpts: []ServerOption{
					WithCertificates(srvCert),
					WithClientAuth(VerifyClientCertIfGiven),
					WithClientCAs(caPool),
				},
				clientAuth:         VerifyClientCertIfGiven,
				expectedServerCert: srvCert.Certificate,
			},
			"VerifyClientCertIfGiven_cert": {
				clientOpts: []ClientOption{WithRootCAs(srvCAPool), WithCertificates(cert)},
				serverOpts: []ServerOption{
					WithCertificates(srvCert),
					WithClientAuth(VerifyClientCertIfGiven),
					WithClientCAs(caPool),
				},
				clientAuth:         VerifyClientCertIfGiven,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
			"VerifyClientCertIfGiven_error": {
				clientOpts:         []ClientOption{WithRootCAs(srvCAPool), WithCertificates(cert)},
				serverOpts:         []ServerOption{WithCertificates(srvCert), WithClientAuth(VerifyClientCertIfGiven)},
				clientAuth:         VerifyClientCertIfGiven,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
				wantErr:            true,
			},
			"RequireAndVerifyClientCert": {
				clientOpts: []ClientOption{
					WithRootCAs(srvCAPool),
					WithCertificates(cert),
					WithVerifyConnection(func(s *State) error {
						if ok := bytes.Equal(s.PeerCertificates[0], srvCertificate.Raw); !ok {
							return errExample
						}

						return nil
					}),
				},
				serverOpts: []ServerOption{
					WithCertificates(srvCert),
					WithClientAuth(RequireAndVerifyClientCert),
					WithClientCAs(caPool),
					WithVerifyConnection(func(s *State) error {
						if ok := bytes.Equal(s.PeerCertificates[0], certificate.Raw); !ok {
							return errExample
						}

						return nil
					}),
				},
				clientAuth:         RequireAndVerifyClientCert,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
			"RequireAndVerifyClientCert_callbacks": {
				clientOpts: []ClientOption{
					WithRootCAs(srvCAPool),
					WithGetClientCertificate(func(*CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }),
				},
				serverOpts: []ServerOption{
					WithGetCertificate(func(*ClientHelloInfo) (*tls.Certificate, error) { return &srvCert, nil }),
					WithClientAuth(RequireAndVerifyClientCert),
					WithClientCAs(caPool),
				},
				clientAuth:         RequireAndVerifyClientCert,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()
				type result struct {
					c          *Conn
					err, hserr error
				}
				clientCh := make(chan result)

				go func() {
					client, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), tt.clientOpts...)
					var hsErr error
					if err == nil {
						hsErr = client.Handshake()
					}
					clientCh <- result{client, err, hsErr}
				}()

				server, err := ServerWithOptions(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), tt.serverOpts...)
				var hserr error
				if err == nil {
					hserr = server.Handshake()
				}
				res := <-clientCh
				defer func() {
					if err == nil {
						_ = server.Close()
					}
					if res.err == nil {
						_ = res.c.Close()
					}
				}()

				if tt.wantErr {
					assert.True(t, err != nil || hserr != nil || res.err != nil || res.hserr != nil, "Error expected")

					return // Error expected, test succeeded
				}
				assert.NoError(t, err)
				assert.NoError(t, res.err)
				assert.NoError(t, hserr)
				assert.NoError(t, res.hserr)

				state, ok := server.ConnectionState()
				assert.True(t, ok, "Server connection state not available")

				actualClientCert := state.PeerCertificates
				if tt.expectedClientCert != nil {
					assert.NotNil(t, actualClientCert, "Client did not provide a certificate")
					assert.Equal(t, actualClientCert[0], tt.expectedClientCert[0], "Client certificate was not communicated correctly")
				}
				if tt.clientAuth == NoClientCert {
					assert.Nil(t, actualClientCert, "Client certificate wasn't expected")
				}

				clientState, ok := res.c.ConnectionState()
				assert.True(t, ok, "Client connection state not available")

				actualServerCert := clientState.PeerCertificates
				assert.NotNil(t, actualServerCert, "server did not provide a certificate")

				assert.NotEmpty(t, tt.expectedServerCert, "Server certificate was not communicated correctly")
				assert.Equal(t, actualServerCert[0], tt.expectedServerCert[0], "Server certificate was not communicated correctly")
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
		clientOpts         []ClientOption
		serverOpts         []ServerOption
		clientConnectionID []byte
		serverConnectionID []byte
	}{
		"BidirectionalConnectionIDs": {
			clientOpts:         []ClientOption{WithConnectionIDGenerator(cidEcho(clientCID))},
			serverOpts:         []ServerOption{WithConnectionIDGenerator(cidEcho(serverCID))},
			clientConnectionID: clientCID,
			serverConnectionID: serverCID,
		},
		"BothSupportOnlyClientSends": {
			clientOpts:         []ClientOption{WithConnectionIDGenerator(cidEcho(nil))},
			serverOpts:         []ServerOption{WithConnectionIDGenerator(cidEcho(serverCID))},
			serverConnectionID: serverCID,
		},
		"BothSupportOnlyServerSends": {
			clientOpts:         []ClientOption{WithConnectionIDGenerator(cidEcho(clientCID))},
			serverOpts:         []ServerOption{WithConnectionIDGenerator(cidEcho(nil))},
			clientConnectionID: clientCID,
		},
		"ClientDoesNotSupport": {
			serverOpts: []ServerOption{WithConnectionIDGenerator(cidEcho(serverCID))},
		},
		"ServerDoesNotSupport": {
			clientOpts: []ClientOption{WithConnectionIDGenerator(cidEcho(clientCID))},
		},
		"NeitherSupport": {},
	}
	for name, tt := range tests {
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
				client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), tt.clientOpts, true)
				c <- result{client, err}
			}()

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), tt.serverOpts, true)
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

			assert.True(t, bytes.Equal(tt.clientConnectionID, res.c.state.GetLocalConnectionID()),
				"Unexpected client local connection ID")
			assert.True(t, bytes.Equal(tt.serverConnectionID, res.c.state.RemoteConnectionID),
				"Unexpected client remote connection ID")
			assert.True(t, bytes.Equal(tt.serverConnectionID, server.state.GetLocalConnectionID()),
				"Unexpected server local connection ID")
			assert.True(t, bytes.Equal(tt.clientConnectionID, server.state.RemoteConnectionID),
				"Unexpected server remote connection ID")
		})
	}
}

func TestExtendedMasterSecret(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	tests := map[string]struct {
		clientOpts        []ClientOption
		serverOpts        []ServerOption
		expectedClientErr error
		expectedServerErr error
	}{
		"Request_Request_ExtendedMasterSecret": {
			clientOpts:        []ClientOption{WithExtendedMasterSecret(RequestExtendedMasterSecret)},
			serverOpts:        []ServerOption{WithExtendedMasterSecret(RequestExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Request_Require_ExtendedMasterSecret": {
			clientOpts:        []ClientOption{WithExtendedMasterSecret(RequestExtendedMasterSecret)},
			serverOpts:        []ServerOption{WithExtendedMasterSecret(RequireExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Request_Disable_ExtendedMasterSecret": {
			clientOpts:        []ClientOption{WithExtendedMasterSecret(RequestExtendedMasterSecret)},
			serverOpts:        []ServerOption{WithExtendedMasterSecret(DisableExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Request_ExtendedMasterSecret": {
			clientOpts:        []ClientOption{WithExtendedMasterSecret(RequireExtendedMasterSecret)},
			serverOpts:        []ServerOption{WithExtendedMasterSecret(RequestExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Require_ExtendedMasterSecret": {
			clientOpts:        []ClientOption{WithExtendedMasterSecret(RequireExtendedMasterSecret)},
			serverOpts:        []ServerOption{WithExtendedMasterSecret(RequireExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Disable_ExtendedMasterSecret": {
			clientOpts:        []ClientOption{WithExtendedMasterSecret(RequireExtendedMasterSecret)},
			serverOpts:        []ServerOption{WithExtendedMasterSecret(DisableExtendedMasterSecret)},
			expectedClientErr: dtlserrors.ErrClientRequiredButNoServerEMS,
			expectedServerErr: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
		},
		"Disable_Request_ExtendedMasterSecret": {
			clientOpts:        []ClientOption{WithExtendedMasterSecret(DisableExtendedMasterSecret)},
			serverOpts:        []ServerOption{WithExtendedMasterSecret(RequestExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Disable_Require_ExtendedMasterSecret": {
			clientOpts:        []ClientOption{WithExtendedMasterSecret(DisableExtendedMasterSecret)},
			serverOpts:        []ServerOption{WithExtendedMasterSecret(RequireExtendedMasterSecret)},
			expectedClientErr: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			expectedServerErr: dtlserrors.ErrServerRequiredButNoClientEMS,
		},
		"Disable_Disable_ExtendedMasterSecret": {
			clientOpts:        []ClientOption{WithExtendedMasterSecret(DisableExtendedMasterSecret)},
			serverOpts:        []ServerOption{WithExtendedMasterSecret(DisableExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
	}
	for name, tt := range tests {
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
				client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), tt.clientOpts, true)
				c <- result{client, err}
			}()

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), tt.serverOpts, true)
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
			clientOpts []ClientOption
			serverOpts []ServerOption
			wantErr    bool
		}{
			"no_ca": {
				serverOpts: []ServerOption{WithCertificates(cert), WithClientAuth(NoClientCert)},
				wantErr:    true,
			},
			"good_ca": {
				clientOpts: []ClientOption{WithRootCAs(caPool)},
				serverOpts: []ServerOption{WithCertificates(cert), WithClientAuth(NoClientCert)},
			},
			"no_ca_skip_verify": {
				clientOpts: []ClientOption{WithInsecureSkipVerify(true)},
				serverOpts: []ServerOption{WithCertificates(cert), WithClientAuth(NoClientCert)},
			},
			"good_ca_skip_verify_custom_verify_peer": {
				clientOpts: []ClientOption{WithRootCAs(caPool), WithCertificates(cert)},
				serverOpts: []ServerOption{
					WithCertificates(cert),
					WithClientAuth(RequireAnyClientCert),
					WithVerifyPeerCertificate(func(_ [][]byte, chain [][]*x509.Certificate) error {
						if len(chain) != 0 {
							return errNotExpectedChain
						}

						return nil
					}),
				},
			},
			"good_ca_verify_custom_verify_peer": {
				clientOpts: []ClientOption{WithRootCAs(caPool), WithCertificates(cert)},
				serverOpts: []ServerOption{
					WithClientCAs(caPool),
					WithCertificates(cert),
					WithClientAuth(RequireAndVerifyClientCert),
					WithVerifyPeerCertificate(func(_ [][]byte, chain [][]*x509.Certificate) error {
						if len(chain) == 0 {
							return errExpecedChain
						}

						return nil
					}),
				},
			},
			"good_ca_custom_verify_peer": {
				clientOpts: []ClientOption{
					WithRootCAs(caPool),
					WithVerifyPeerCertificate(func([][]byte, [][]*x509.Certificate) error {
						return errWrongCert
					}),
				},
				serverOpts: []ServerOption{WithCertificates(cert), WithClientAuth(NoClientCert)},
				wantErr:    true,
			},
			"server_name": {
				clientOpts: []ClientOption{WithRootCAs(caPool), WithServerName(certificate.Subject.CommonName)},
				serverOpts: []ServerOption{WithCertificates(cert), WithClientAuth(NoClientCert)},
			},
			"server_name_error": {
				clientOpts: []ClientOption{WithRootCAs(caPool), WithServerName("barfoo")},
				serverOpts: []ServerOption{WithCertificates(cert), WithClientAuth(NoClientCert)},
				wantErr:    true,
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()

				type result struct {
					c          *Conn
					err, hserr error
				}
				srvCh := make(chan result)
				go func() {
					s, err := ServerWithOptions(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), tt.serverOpts...)
					var hsErr error
					if err == nil {
						hsErr = s.Handshake()
					}
					srvCh <- result{s, err, hsErr}
				}()

				cli, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), tt.clientOpts...)
				var hserr error
				if err == nil {
					hserr = cli.Handshake()
				}
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
			Name:               "No cipherSuites specified",
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
			Name:                    "Valid cipherSuites specified",
			ClientCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		{
			Name:               "cipherSuites mismatch",
			ClientCipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
			WantClientError:    &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			WantServerError:    dtlserrors.ErrCipherSuiteNoIntersection,
		},
		{
			Name:                    "Valid cipherSuites CCM specified",
			ClientCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_CCM},
			ServerCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_CCM},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		},
		{
			Name:                    "Valid cipherSuites CCM-8 specified",
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
				var opts []ClientOption
				if len(test.ClientCipherSuites) > 0 {
					opts = append(opts, WithCipherSuites(test.ClientCipherSuites...))
				}
				client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts, true)
				resultCh <- result{client, err}
			}()

			var opts []ServerOption
			if len(test.ServerCipherSuites) > 0 {
				opts = append(opts, WithCipherSuites(test.ServerCipherSuites...))
			}
			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), opts, true)
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
				assert.Equal(t, test.WantSelectedCipherSuite, res.c.state.CipherSuite.ID(),
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
			Name:      "Client uses psk",
			ClientPSK: true,
		},
	} {
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
				opts := []ClientOption{WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}
				if test.ClientPSK {
					opts = []ClientOption{
						WithPSK(func([]byte) ([]byte, error) {
							return []byte{0x00, 0x01, 0x02}, nil
						}),
						WithPSKIdentityHint([]byte{0x00}),
						WithCipherSuites(TLS_PSK_WITH_AES_128_GCM_SHA256),
					}
				}

				client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts, false)
				resultCh <- result{client, err}
			}()

			opts := []ServerOption{
				WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_PSK_WITH_AES_128_GCM_SHA256),
				WithPSK(func([]byte) ([]byte, error) {
					return []byte{0x00, 0x01, 0x02}, nil
				}),
			}

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), opts, true)
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
			Name:                 "psk and no certificate specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      dtlserrors.ErrNoAvailablePSKCipherSuite,
			WantServerError:      dtlserrors.ErrNoAvailablePSKCipherSuite,
		},
		{
			Name:                 "psk and certificate specified",
			ClientHasCertificate: true,
			ServerHasCertificate: true,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      dtlserrors.ErrNoAvailablePSKCipherSuite,
			WantServerError:      dtlserrors.ErrNoAvailablePSKCipherSuite,
		},
		{
			Name:                 "psk and no identity specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    nil,
			ServerPSKIdentity:    nil,
			WantClientError:      dtlserrors.ErrPSKAndIdentityMustBeSetForClient,
			WantServerError:      dtlserrors.ErrNoAvailablePSKCipherSuite,
		},
		{
			Name:                 "No psk and identity specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            nil,
			ServerPSK:            nil,
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      dtlserrors.ErrIdentityNoPSK,
			WantServerError:      dtlserrors.ErrIdentityNoPSK,
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
			var opts []ClientOption
			if test.ClientPSK != nil {
				opts = append(opts, WithPSK(test.ClientPSK))
			}
			if test.ClientPSKIdentity != nil {
				opts = append(opts, WithPSKIdentityHint(test.ClientPSKIdentity))
			}
			client, err := testClient(
				ctx,
				dtlsnet.PacketConnFromConn(ca),
				ca.RemoteAddr(),
				opts,
				test.ClientHasCertificate,
			)
			resultCh <- result{client, err}
		}()

		var opts []ServerOption
		if test.ServerPSK != nil {
			opts = append(opts, WithPSK(test.ServerPSK))
		}
		if test.ServerPSKIdentity != nil {
			opts = append(opts, WithPSKIdentityHint(test.ServerPSKIdentity))
		}
		_, err := testServer(
			ctx,
			dtlsnet.PacketConnFromConn(cb),
			cb.RemoteAddr(),
			opts,
			test.ServerHasCertificate,
		)
		if err != nil || test.WantServerError != nil {
			if err == nil || test.WantServerError == nil || err.Error() != test.WantServerError.Error() {
				assert.Failf(t, "TestPSKConfiguration", "Server Error Mismatch '%s'", test.Name)
			}
		}

		res := <-resultCh
		if res.err != nil || test.WantClientError != nil {
			if res.err == nil || test.WantClientError == nil && res.err.Error() != test.WantClientError.Error() {
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

	serverOpts := []ServerOption{
		WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		WithFlightInterval(100 * time.Millisecond),
	}

	_, serverErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), serverOpts, true)
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

	clientOpts := []ClientOption{
		WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		WithFlightInterval(100 * time.Millisecond),
	}
	serverOpts := []ServerOption{
		WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		WithFlightInterval(100 * time.Millisecond),
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
						serverOpts,
						true,
					)
					assert.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
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
					_, err := testClient(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), clientOpts, true)
					assert.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
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

type rawExtension13 struct {
	typeValue extension.TypeValue
	raw       []byte
}

func (e rawExtension13) Marshal() ([]byte, error) {
	return append([]byte(nil), e.raw...), nil
}

func (e rawExtension13) Unmarshal([]byte) error {
	return nil
}

func (e rawExtension13) TypeValue() extension.TypeValue {
	return e.typeValue
}

func marshalVersionNegotiationHelloRetryRequestServerHello13(
	t *testing.T,
	cfg *handshakeConfig,
	extensions []extension.Extension,
) []byte {
	t.Helper()

	var hrrRandomFixed [handshake.RandomLength]byte
	copy(hrrRandomFixed[:], handshake.HelloRetryRequestRandom())
	var hrrRandom handshake.Random
	hrrRandom.UnmarshalFixed(hrrRandomFixed)

	return marshalVersionNegotiationServerHello13(t, cfg, hrrRandom, extensions)
}

func marshalVersionNegotiationServerHello13(
	t *testing.T,
	cfg *handshakeConfig,
	random handshake.Random,
	extensions []extension.Extension,
) []byte {
	t.Helper()

	cipherSuiteID := uint16(cfg.LocalCipherSuites[0].ID())
	serverHello := &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		Random:            random,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: defaultCompressionMethods()[0],
		Extensions:        extensions,
	}
	rawServerHello, err := (&handshake.Handshake{Message: serverHello}).Marshal()
	assert.NoError(t, err)

	return rawServerHello
}

func testVersionNegotiationHandshakeConfig13(t *testing.T) *handshakeConfig {
	t.Helper()

	cipherSuites, err := parseCipherSuitesForVersions(
		nil,
		nil,
		true,
		false,
		protocol.Version1_3,
		protocol.Version1_3,
	)
	assert.NoError(t, err)

	loggerFactory := logging.NewDefaultLoggerFactory()

	return &handshakeConfig{
		LocalCipherSuites:           cipherSuites,
		EllipticCurves:              defaultCurves,
		InitialRetransmitInterval:   time.Second,
		ExtendedMasterSecret:        dtlsconfig.ExtendedMasterSecretType(RequestExtendedMasterSecret),
		Log:                         loggerFactory.NewLogger("dtls"),
		MinVersion:                  protocol.Version1_3,
		MaxVersion:                  protocol.Version1_3,
		LocalSignatureSchemes:       signaturehash.Algorithms13(),
		LocalCertSignatureSchemes:   nil,
		LocalSRTPProtectionProfiles: nil,
	}
}

func TestPickVersionFromServerResponseRejectsHelloRetryRequestWithoutSupportedVersions(t *testing.T) {
	cfg := testVersionNegotiationHandshakeConfig13(t)
	cfg.MinVersion = protocol.Version1_2
	cfg.MaxVersion = protocol.Version1_3
	selectedGroup := elliptic.P384

	rawServerHello := marshalVersionNegotiationHelloRetryRequestServerHello13(
		t,
		cfg,
		[]extension.Extension{
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	conn := &Conn{
		handshakeCache:  dtlsflight.NewCache(),
		handshakeConfig: cfg,
	}
	conn.handshakeCache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	ok, err := conn.pickVersionFromServerResponse()

	assert.ErrorIs(t, err, dtlserrors.ErrInvalidHelloRetryRequest)
	assert.False(t, ok)
	assert.Equal(t, protocol.Version{}, conn.state.LocalVersion)
}

func TestPickVersionFromServerResponseRejectsServerHelloWithClientHelloSupportedVersionsEncoding(t *testing.T) {
	cfg := testVersionNegotiationHandshakeConfig13(t)
	cfg.MinVersion = protocol.Version1_2
	cfg.MaxVersion = protocol.Version1_3
	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}

	rawServerHello := marshalVersionNegotiationServerHello13(
		t,
		cfg,
		random,
		[]extension.Extension{
			rawExtension13{
				typeValue: extension.SupportedVersionsTypeValue,
				raw: []byte{
					0x00, 0x2b, // supported_versions
					0x00, 0x03, // extension_data length
					0x02,       // ClientHello vector length
					0xfe, 0xfc, // DTLS v1.3
				},
			},
		},
	)

	conn := &Conn{
		handshakeCache:  dtlsflight.NewCache(),
		handshakeConfig: cfg,
	}
	conn.handshakeCache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	ok, err := conn.pickVersionFromServerResponse()

	assert.ErrorIs(t, err, dtlserrors.ErrInvalidServerHello)
	assert.False(t, ok)
	assert.Equal(t, protocol.Version{}, conn.state.LocalVersion)
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
	for i := range 2 {
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
		_, _ = testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), nil, false)
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
		Name                     string
		ExpectRenegotiationInfo  bool
		SendRenegotiationInfoExt bool
		IncludeRenegotiationSCSV bool
	}{
		{
			Name:                     "Include RenegotiationInfo",
			ExpectRenegotiationInfo:  true,
			SendRenegotiationInfoExt: true,
		},
		{
			Name:                     "RenegotiationInfo SCSV",
			ExpectRenegotiationInfo:  true,
			IncludeRenegotiationSCSV: true,
		},
		{
			Name:                    "No RenegotiationInfo",
			ExpectRenegotiationInfo: false,
		},
	} {
		test := testCase
		t.Run(test.Name, func(t *testing.T) {
			ca, cb := dpipe.Pipe()
			defer func() {
				assert.NoError(t, ca.Close())
			}()

			ctx := t.Context()

			go func() {
				_, err := testServer(
					ctx,
					dtlsnet.PacketConnFromConn(cb),
					cb.RemoteAddr(),
					nil,
					true,
				)
				assert.ErrorIs(t, err, context.Canceled)
			}()

			time.Sleep(50 * time.Millisecond)

			extensions := []extension.Extension{}
			if test.SendRenegotiationInfoExt {
				extensions = append(extensions, &extension.RenegotiationInfo{
					RenegotiatedConnection: 0,
				})
			}
			cipherSuites := cipherSuiteIDs(defaultCipherSuites())
			if test.IncludeRenegotiationSCSV {
				cipherSuites = append(cipherSuites, renegotiationInfoSCSV)
			}
			err := sendClientHello([]byte{}, ca, 0, extensions, cipherSuites...)
			assert.NoError(t, err)

			n, err := ca.Read(resp)
			assert.NoError(t, err)

			record := &recordlayer.RecordLayer{}
			assert.NoError(t, record.Unmarshal(resp[:n]))

			helloVerifyRequest, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageHelloVerifyRequest)
			assert.True(t, ok)

			err = sendClientHello(helloVerifyRequest.Cookie, ca, 1, extensions, cipherSuites...)
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
		serverName string
		Expected   []byte
		IncludeSNI bool
	}{
		{
			Name:       "Server name is a valid hostname",
			serverName: "example.com", //nolint:goconst
			Expected:   []byte("example.com"),
			IncludeSNI: true,
		},
		{
			Name:       "Server name is an IP literal",
			serverName: "1.2.3.4",
			Expected:   []byte(""),
			IncludeSNI: false,
		},
		{
			Name:       "Server name is empty",
			serverName: "",
			Expected:   []byte(""),
			IncludeSNI: false,
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			go func() {
				_, _ = testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), []ClientOption{
					WithServerName(test.serverName),
				}, false)
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
			ClientProtocolNameList: []string{"http/1.1", "spd/1"}, //nolint:goconst
			ServerProtocolNameList: []string{"spd/1"},
			ExpectedProtocol:       "spd/1", //nolint:goconst
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
			ExpectedProtocol:       "http/3", //nolint:goconst
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
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			go func() {
				var opts []ClientOption
				if len(test.ClientProtocolNameList) > 0 {
					opts = append(opts, WithSupportedProtocols(test.ClientProtocolNameList...))
				}
				_, _ = testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts, false)
			}()

			// Receive ClientHello
			resp := make([]byte, 1024)
			n, err := cb.Read(resp)
			assert.NoError(t, err)

			ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel2()

			ca2, cb2 := dpipe.Pipe()
			go func() {
				var opts []ServerOption
				if len(test.ServerProtocolNameList) > 0 {
					opts = append(opts, WithSupportedProtocols(test.ServerProtocolNameList...))
				}
				_, err2 := testServer(ctx2, dtlsnet.PacketConnFromConn(cb2), cb2.RemoteAddr(), opts, true)
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
			_, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), nil, true)
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
			opts := []ClientOption{
				WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				WithServerName("example.com"),
				WithSessionStore(ss),
				WithMTU(100),
			}
			c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts, false)
			clientRes <- result{c, err}
		}()

		opts := []ServerOption{
			WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			WithServerName("example.com"),
			WithSessionStore(ss),
			WithMTU(100),
		}
		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), opts, true)
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
			opts := []ClientOption{
				WithServerName("example.com"),
				WithSessionStore(s1),
			}
			c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts, false)
			clientRes <- result{c, err}
		}()

		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), []ServerOption{
			WithSessionStore(s2),
		}, true)
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
		t.Run(test.Name, func(t *testing.T) {
			clientErr := make(chan error, 1)
			client := make(chan *Conn, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				c, err := testClient(context.TODO(), dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), []ClientOption{
					WithCipherSuites(test.cipherList...),
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

			s, err := testServer(context.TODO(), dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), []ServerOption{
				WithCipherSuites(test.cipherList...),
				WithCertificates(serverCert),
			}, false)
			assert.NoError(t, err)
			assert.NoError(t, s.Close())

			c := <-client
			assert.NoError(t, <-clientErr)
			assert.NoError(t, c.Close())

			state, ok := c.ConnectionState()
			assert.True(t, ok)
			assert.Equal(t, test.expectedCipher, state.CipherSuiteID)
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
			"foo", //nolint:goconst
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
		t.Run(test.RequestServerName, func(t *testing.T) {
			clientErr := make(chan error, 2)
			client := make(chan *Conn, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				clientConn, err := testClient(context.TODO(), dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), []ClientOption{
					WithRootCAs(caPool),
					WithServerName(test.RequestServerName),
					WithVerifyPeerCertificate(func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
						certificate, err := x509.ParseCertificate(rawCerts[0])
						if err != nil {
							return err
						}

						if certificate.DNSNames[0] != test.ExpectedDNSName {
							return errWrongCert
						}

						return nil
					}),
				}, false)
				clientErr <- err
				client <- clientConn
			}()

			s, err := testServer(context.TODO(), dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), []ServerOption{
				WithCertificates(fooCert, barCert),
			}, false)
			assert.NoError(t, err)
			assert.NoError(t, <-clientErr)
			assert.NoError(t, s.Close())
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
			opts := []ClientOption{WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}
			if len(test.ConfigCurves) > 0 {
				opts = append(opts, WithEllipticCurves(test.ConfigCurves...))
			}
			client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts, true)
			resultCh <- result{client, err}
		}()

		opts := []ServerOption{WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}
		if len(test.ConfigCurves) > 0 {
			opts = append(opts, WithEllipticCurves(test.ConfigCurves...))
		}
		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), opts, true)
		assert.NoError(t, err)

		ok := len(test.ConfigCurves) == 0 || len(test.ConfigCurves) == len(test.HandshakeCurves)
		assert.True(t, ok, "Failed to default Elliptic curves")

		if len(test.ConfigCurves) != 0 {
			assert.Equal(
				t,
				len(test.HandshakeCurves),
				len(server.handshakeConfig.EllipticCurves),
				"Failed to configure Elliptic curves",
			)

			for i, c := range test.ConfigCurves {
				assert.Equal(
					t,
					c,
					server.handshakeConfig.EllipticCurves[i],
					"Failed to maintain Elliptic curve order",
				)
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
		server, sErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), []ServerOption{
			WithCertificates(certificate),
			WithLoggerFactory(logging.NewDefaultLoggerFactory()),
			WithInsecureSkipVerifyHello(true),
		}, false)
		assert.NoError(t, sErr)

		buf := make([]byte, 1024)
		_, sErr = server.Read(buf) //nolint:contextcheck
		assert.NoError(t, sErr)
		gotHello <- struct{}{}
		assert.NoError(t, server.Close()) //nolint:contextcheck
	}()

	client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), []ClientOption{
		WithLoggerFactory(logging.NewDefaultLoggerFactory()),
		WithInsecureSkipVerify(true),
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

		dconn, err := ServerWithOptions(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), WithCertificates(serverCert))
		assert.NoError(t, err)

		go func() {
			for range 5 {
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

	for i := range 1000 {
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

func TestHandleIncomingPacket13QueuesHandshakeEpochBeforeProtection(t *testing.T) {
	conn := &Conn{
		fragmentBuffer:         newFragmentBuffer(),
		handshakeCache:         dtlsflight.NewCache(),
		log:                    logging.NewDefaultLoggerFactory().NewLogger("dtls"),
		replayProtectionWindow: defaultReplayProtectionWindow,
		handshakeConfig:        testVersionNegotiationHandshakeConfig13(t),
		state:                  dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3},
	}
	conn.setRemoteEpoch(0)

	rawPacket, err := (&recordlayer.RecordLayer{
		Header: recordlayer.Header{
			Version:        protocol.Version1_2,
			Epoch:          dtlsflight13.EpochHandshake,
			SequenceNumber: 0,
		},
		Content: &handshake.Handshake{
			Header:  handshake.Header{MessageSequence: 1},
			Message: &handshake.MessageEncryptedExtensions{},
		},
	}).Marshal()
	assert.NoError(t, err)

	isHandshake, isRetransmit, dtlsAlert, err := conn.handleIncomingPacket(
		context.Background(),
		rawPacket,
		nil,
		true,
	)
	assert.NoError(t, err)
	assert.Nil(t, dtlsAlert)
	assert.False(t, isHandshake)
	assert.False(t, isRetransmit)
	assert.Len(t, conn.encryptedPackets, 1)
	assert.Equal(t, rawPacket, conn.encryptedPackets[0].data)
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
		server, sErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), []ServerOption{
			WithGetCertificate(func(chi *ClientHelloInfo) (*tls.Certificate, error) {
				if len(chi.CipherSuites) == 0 {
					return &certificate, nil
				}
				assert.Equal(t, chRandom[:], chi.RandomBytes[:])

				return &certificate, nil
			}),
			WithLoggerFactory(logging.NewDefaultLoggerFactory()),
		}, false)
		assert.NoError(t, sErr)

		buf := make([]byte, 1024)
		_, sErr = server.Read(buf) //nolint:contextcheck
		assert.NoError(t, sErr)

		gotHello <- struct{}{}
		assert.NoError(t, server.Close()) //nolint:contextcheck
	}()

	client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), []ClientOption{
		WithLoggerFactory(logging.NewDefaultLoggerFactory()),
		WithHelloRandomBytesGenerator(func() [handshake.RandomBytesLength]byte {
			return chRandom
		}),
		WithInsecureSkipVerify(true),
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
		_, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), nil, true)
		clientErr <- err
	}()

	expectedErr := errConnectionAttemptFailed
	_, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), []ServerOption{
		WithOnConnectionAttempt(func(in net.Addr) error {
			serverOnConnectionAttempt.Store(1)
			assert.NotNil(t, in)

			return expectedErr
		}),
	}, true)
	assert.ErrorIs(t, err, expectedErr)
	assert.Error(t, <-clientErr)
	assert.Equal(t, int32(1), serverOnConnectionAttempt.Load(), "onConnectionAttempt did not fire for server")
	assert.Equal(t, int32(0), clientOnConnectionAttempt.Load(), "onConnectionAttempt fired for client")
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
	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	client, err := ClientWithOptions(
		dtlsnet.PacketConnFromConn(ca),
		ca.RemoteAddr(),
		WithCertificates(clientCert),
		WithInsecureSkipVerify(true),
	)
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
	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), nil, true)
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

	server, err := ServerWithOptions(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), WithCertificates(serverCert))
	assert.NoError(t, err)

	go func() {
		_ = server.Handshake()
	}()

	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	client, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), WithCertificates(clientCert))
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

	for range 100 {
		_, cb := dpipe.Pipe()
		server, err := ServerWithOptions(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), WithCertificates(serverCert))
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
	server, err := ServerWithOptions(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), WithCertificates(serverCert))
	assert.NoError(t, err)
	assert.NoError(t, server.Close())
}

// WIP! Tests if DTLS 1.3 handshake flow is enabled and the correct error is returned.
func TestDTLS13Enabled(t *testing.T) {
	ca, cb := dpipe.Pipe()

	// Setup client
	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	client, err := ClientWithOptions(
		dtlsnet.PacketConnFromConn(ca),
		ca.RemoteAddr(),
		WithCertificates(clientCert),
		WithInsecureSkipVerify(true),
		WithMinVersion(protocol.Version1_3),
		WithMaxVersion(protocol.Version1_3),
	)
	assert.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	_, ok := client.ConnectionState()
	assert.False(t, ok)

	ctxClient, cancelClient := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClient()
	errorChannel := make(chan error)
	go func() {
		errC := client.HandshakeContext(ctxClient)
		errorChannel <- errC
	}()

	err = <-errorChannel
	assert.Error(t, err)
	assert.ErrorIs(t, err, dtlserrors.ErrStateUnimplemented13)

	// Setup server
	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	server, err := ServerWithOptions(
		dtlsnet.PacketConnFromConn(cb),
		cb.RemoteAddr(),
		WithCertificates(serverCert),
		WithInsecureSkipVerify(true),
		WithMinVersion(protocol.Version1_3),
		WithMaxVersion(protocol.Version1_3),
	)
	assert.NoError(t, err)
	defer func() {
		_ = server.Close()
	}()

	_, ok = server.ConnectionState()
	assert.False(t, ok)

	ctxServer, cancelServer := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelServer()
	go func() {
		errS := server.HandshakeContext(ctxServer)
		errorChannel <- errS
	}()
	err = <-errorChannel
	assert.Error(t, err)
	assert.ErrorIs(t, err, dtlserrors.ErrStateUnimplemented13)
}

// WIP! Tests if the dual stack mode client managed to negotiate a version successfully.
func TestDTLSDualStackClient(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	// Setup client
	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	clientOpts := []ClientOption{
		WithCertificates(clientCert),
		WithInsecureSkipVerify(true),
		WithMinVersion(protocol.Version1_2),
		WithMaxVersion(protocol.Version1_3),
	}

	// Setup server
	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	serverOpts := []ServerOption{
		WithCertificates(serverCert),
		WithInsecureSkipVerify(true),
		WithMinVersion(protocol.Version1_2),
		WithMaxVersion(protocol.Version1_2),
	}

	testDTLSDualStack(t, clientOpts, serverOpts)
}

func TestDTLSDualStackClientRejectsNonClientHelloBeforeWrite(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 5).Stop()

	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	var writes atomic.Int32
	caCount := &connWithCallback{
		Conn: ca,
		onWrite: func([]byte) {
			writes.Add(1)
		},
	}

	cipherSuiteID := uint16(ciphersuite.TLS_AES_128_GCM_SHA256)
	client, err := ClientWithOptions(
		dtlsnet.PacketConnFromConn(caCount),
		caCount.RemoteAddr(),
		WithInsecureSkipVerify(true),
		WithMinVersion(protocol.Version1_2),
		WithMaxVersion(protocol.Version1_3),
		WithClientHelloMessageHook(func(handshake.MessageClientHello) handshake.Message {
			return &handshake.MessageServerHello{
				Version:           protocol.Version1_2,
				CipherSuiteID:     &cipherSuiteID,
				CompressionMethod: defaultCompressionMethods()[0],
			}
		}),
	)
	if !assert.NoError(t, err) {
		return
	}
	defer func() {
		_ = client.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = client.HandshakeContext(ctx)
	assert.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptMissingClientHello)
	assert.Equal(t, int32(0), writes.Load())
}

// WIP! Tests if the dual stack mode server managed to negotiate a version successfully.
func TestDTLSDualStackServer(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	// Setup client
	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	clientOpts := []ClientOption{
		WithCertificates(clientCert),
		WithInsecureSkipVerify(true),
		WithMinVersion(protocol.Version1_2),
		WithMaxVersion(protocol.Version1_2),
	}

	// Setup server
	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	serverOpts := []ServerOption{
		WithCertificates(serverCert),
		WithInsecureSkipVerify(true),
		WithMinVersion(protocol.Version1_2),
		WithMaxVersion(protocol.Version1_3),
	}

	testDTLSDualStack(t, clientOpts, serverOpts)
}

// WIP! Tests if the dual stack mode managed to negotiate a version successfully.
func testDTLSDualStack(t *testing.T, clientOpts []ClientOption, serverOpts []ServerOption) {
	t.Helper()
	ca, cb := dpipe.Pipe()

	client, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), clientOpts...)
	assert.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	_, ok := client.ConnectionState()
	assert.False(t, ok)

	ctxClient, cancelClient := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClient()
	errorChannel := make(chan error, 2)

	server, err := ServerWithOptions(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), serverOpts...)
	assert.NoError(t, err)
	defer func() {
		_ = server.Close()
	}()

	_, ok = server.ConnectionState()
	assert.False(t, ok)

	ctxServer, cancelServer := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelServer()

	go func() {
		errC := client.HandshakeContext(ctxClient)
		errorChannel <- errC
	}()

	go func() {
		errS := server.HandshakeContext(ctxServer)
		errorChannel <- errS
	}()

	err = <-errorChannel
	assert.NoError(t, err)

	err = <-errorChannel
	assert.NoError(t, err)

	assert.NoError(t, server.Close())
	assert.NoError(t, client.Close())
}
