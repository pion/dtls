// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v4/internal/ciphersuite"
	"github.com/pion/dtls/v4/internal/closer"
	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v4/internal/flight/flight13"
	dtlsfragmentbuffer "github.com/pion/dtls/v4/internal/fragmentbuffer"
	dtlshandshake "github.com/pion/dtls/v4/internal/handshake"
	"github.com/pion/dtls/v4/internal/negotiation"
	"github.com/pion/dtls/v4/internal/recordwire"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/pion/transport/v5/dpipe"
	"github.com/pion/transport/v5/netctx"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func defaultCipherSuites() []cryptosuite.Suite {
	return defaultCipherSuitesForVersion(protocol.Version1_2)
}

func cipherSuiteIDs(suites []cryptosuite.Suite) []uint16 {
	ids := make([]uint16, len(suites))
	for i, suite := range suites {
		ids[i] = uint16(suite.ID())
	}

	return ids
}

func marshalTestRecord(header recordlayer.RecordConfig, content protocol.Content) ([]byte, error) {
	payload, err := content.Marshal()
	if err != nil {
		return nil, err
	}

	header.ContentType = content.ContentType()

	return recordlayer.MarshalRecord(header, payload)
}

func TestMarshalRecordContentEnforcesPlaintextLimit(t *testing.T) {
	_, plaintext, err := marshalRecordContent(&protocol.ApplicationData{
		Data: make([]byte, maxPlaintextRecordLen),
	})
	require.NoError(t, err)
	assert.Len(t, plaintext, maxPlaintextRecordLen)

	_, _, err = marshalRecordContent(&protocol.ApplicationData{
		Data: make([]byte, maxPlaintextRecordLen+1),
	})
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidPacketLength)
}

func TestApplicationDataPacketOwnsPayload(t *testing.T) {
	conn := &Conn{state: dtlsstate.NewActive(true)}
	payload := []byte("application data")
	packet := conn.newApplicationDataPacket(payload)
	payload[0] = 'X'

	applicationData, ok := packet.Content.(*protocol.ApplicationData)
	require.True(t, ok)
	assert.Equal(t, []byte("application data"), applicationData.Data)
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

		dtlsstate.CommonState(ca.state).SetLocalSequenceNumber(1, recordlayer.MaxSequenceNumber)
		n, werr := ca.Write(make([]byte, 100))
		assert.NoError(t, werr, "Write must send message with maximum sequence number")
		assert.Equal(t, 100, n)
		n, werr = ca.Write(make([]byte, 100))
		assert.ErrorIs(t, werr, dtlserrors.ErrSequenceNumberOverflow, "Write must abandonsend message with maximum sequence number")
		assert.Zero(t, n)

		assert.NoError(t, ca.Close())
		assert.NoError(t, cb.Close())
	})
	t.Run("Handshake", func(t *testing.T) {
		ca, cb, err := pipeMemory()
		assert.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		dtlsstate.CommonState(ca.state).SetLocalSequenceNumber(0, recordlayer.MaxSequenceNumber+1)

		// Try to send handshake packet.
		werr := ca.writePackets(ctx, []*dtlsflight.Outbound{{Content: &handshake.Handshake{Message: &handshake.MessageClientHello{Version: protocol.Version1_2, Cookie: make([]byte, 64), CipherSuiteIDs: cipherSuiteIDs(defaultCipherSuites()), CompressionMethods: dtlsflight.DefaultCompressionMethods()}}}})
		assert.ErrorIs(t, werr, dtlserrors.ErrSequenceNumberOverflow, "Connection must fail when handshake packet reaches maximum sequence num")
		assert.NoError(t, ca.Close())
		assert.NoError(t, cb.Close())
	})
}

type packetTestConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *packetTestConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)

	return n, c.remoteAddr, err
}

func (c *packetTestConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(p)
}

func (c *packetTestConn) RemoteAddr() net.Addr { return c.remoteAddr }

func packetPipe() (*packetTestConn, *packetTestConn) {
	a, b := dpipe.Pipe()

	return &packetTestConn{Conn: a, remoteAddr: b.LocalAddr()},
		&packetTestConn{Conn: b, remoteAddr: a.LocalAddr()}
}

func pipeMemory() (*Conn, *Conn, error) {
	// In memory pipe
	ca, cb := packetPipe()

	return pipeConn(ca, cb)
}

func pipeConn(ca, cb net.PacketConn) (*Conn, *Conn, error) {
	type result struct {
		c   *Conn
		err error
	}

	resultCh := make(chan result, 1) // Buffered to prevent goroutine leak
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Setup client
	go func() {
		client, err := testClient(ctx, ca, cb.LocalAddr(), []ClientOption{WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80)}, true)
		resultCh <- result{client, err}
	}()

	// Setup server
	server, err := testServer(ctx, cb, ca.LocalAddr(), []ServerOption{WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80)}, true)
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

func testClient(ctx context.Context, pktConn net.PacketConn, rAddr net.Addr, opts []ClientOption, generateCertificate bool) (*Conn, error) {
	if generateCertificate {
		clientCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		opts = append(opts, WithCertificates(clientCert))
	}
	opts = append(opts, WithInsecureSkipVerify(true))
	conn, err := Client(pktConn, rAddr, opts...)
	if err != nil {
		return nil, err
	}

	return conn, conn.HandshakeContext(ctx)
}

func testServer(ctx context.Context, c net.PacketConn, rAddr net.Addr, opts []ServerOption, generateCertificate bool) (*Conn, error) {
	if generateCertificate {
		serverCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		opts = append(opts, WithCertificates(serverCert))
	}
	conn, err := Server(c, rAddr, opts...)
	if err != nil {
		return nil, err
	}

	return conn, conn.HandshakeContext(ctx)
}

type handshakeResult struct {
	conn           *Conn
	configErr      error
	handshakeError error
}

func handshakePair(t *testing.T, clientOpts []ClientOption, serverOpts []ServerOption) (handshakeResult, handshakeResult) {
	t.Helper()
	ca, cb := packetPipe()
	t.Cleanup(func() {
		_ = ca.Close()
		_ = cb.Close()
	})
	clientCh := make(chan handshakeResult)
	go func() {
		client, err := Client(ca, ca.RemoteAddr(), clientOpts...)
		var handshakeErr error
		if err == nil {
			handshakeErr = client.Handshake()
		}
		clientCh <- handshakeResult{client, err, handshakeErr}
	}()
	server, err := Server(cb, cb.RemoteAddr(), serverOpts...)
	var handshakeErr error
	if err == nil {
		handshakeErr = server.Handshake()
	}
	clientResult := <-clientCh
	serverResult := handshakeResult{server, err, handshakeErr}
	t.Cleanup(func() {
		if clientResult.conn != nil {
			_ = clientResult.conn.Close()
		}
		if serverResult.conn != nil {
			_ = serverResult.conn.Close()
		}
	})

	return clientResult, serverResult
}

//nolint:unused // Used by Go 1.25+ tests in sync_test.go.
func sendClientHello(cookie []byte, ca net.Conn, sequenceNumber uint64, extensions []extension.Value, cipherSuiteIDsOverride ...uint16) error {
	cipherSuites := cipherSuiteIDsOverride
	if len(cipherSuites) == 0 {
		cipherSuites = cipherSuiteIDs(defaultCipherSuites())
	}

	clientHello := handshake.MessageClientHello{Version: protocol.Version1_2, Cookie: cookie, CipherSuiteIDs: cipherSuites, CompressionMethods: dtlsflight.DefaultCompressionMethods(), Extensions: extensions}

	packet, err := marshalTestRecord(recordlayer.RecordConfig{
		Version:        protocol.Version1_2,
		SequenceNumber: sequenceNumber,
	}, &handshake.Handshake{
		Header: handshake.Header{
			MessageSequence: uint16(sequenceNumber), //nolint:gosec // G115
		},
		Message: &clientHello,
	})
	if err != nil {
		return err
	}

	if _, err = ca.Write(packet); err != nil {
		return err
	}

	return nil
}

func TestExportKeyingMaterial(t *testing.T) {
	const exportLabel = "EXTRACTOR-dtls_srtp"

	for _, tt := range []struct {
		name              string
		version           protocol.Version
		cipherSuite       cryptosuite.ID
		expectedServerKey string
		expectedClientKey string
		contextErr        error
		labelErr          error
	}{
		{
			name: "DTLS12", version: protocol.Version1_2,
			cipherSuite:       cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			expectedServerKey: "61099d7dcb08522ce77b",
			expectedClientKey: "87f04002f61cf1fe8c77",
			contextErr:        dtlserrors.ErrContextUnsupported,
			labelErr:          dtlserrors.ErrReservedExportKeyingMaterial,
		},
		{
			name: "DTLS13", version: protocol.Version1_3,
			cipherSuite:       cryptosuite.TLS_AES_128_GCM_SHA256,
			expectedServerKey: "31361451e3d8dc3ad264",
			expectedClientKey: "31361451e3d8dc3ad264",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			common := &dtlsstate.Common{
				LocalRandom:         handshake.Random{GMTUnixTime: time.Unix(500, 0)},
				RemoteRandom:        handshake.Random{GMTUnixTime: time.Unix(1000, 0)},
				LocalSequenceNumber: map[uint64]uint64{},
				CipherSuite:         ciphersuite.ForID(tt.cipherSuite),
			}
			conn := &Conn{state: &dtlsstate.State12{Common: common}}
			if tt.version == protocol.Version1_3 {
				conn.state = &dtlsstate.State13{
					Common:      common,
					KeySchedule: dtlsstate.KeySchedule{ExporterMasterSecret: make([]byte, 32)},
				}
			}

			state, ok := conn.ConnectionState()
			require.True(t, ok)
			_, err := state.ExportKeyingMaterial(exportLabel, nil, 10)
			assert.ErrorIs(t, err, dtlserrors.ErrHandshakeInProgress)

			conn.setLocalEpoch(1)
			for _, role := range []struct {
				name     string
				isClient bool
				expected string
			}{
				{name: "server", expected: tt.expectedServerKey},
				{name: "client", isClient: true, expected: tt.expectedClientKey},
			} {
				t.Run(role.name, func(t *testing.T) {
					common.IsClient = role.isClient
					state, ok := conn.ConnectionState()
					require.True(t, ok)

					keyingMaterial, err := state.ExportKeyingMaterial(exportLabel, nil, 10)
					require.NoError(t, err)
					assert.Equal(t, role.expected, hex.EncodeToString(keyingMaterial))

					otherMaterial, err := state.ExportKeyingMaterial("EXPORTER-other", nil, 10)
					require.NoError(t, err)
					assert.NotEqual(t, keyingMaterial, otherMaterial)

					contextMaterial, err := state.ExportKeyingMaterial(exportLabel, []byte{0x00}, 10)
					assert.ErrorIs(t, err, tt.contextErr)
					if tt.contextErr == nil {
						assert.Len(t, contextMaterial, 10)
						assert.NotEqual(t, keyingMaterial, contextMaterial)
					}

					for label := range invalidKeyingLabels() {
						_, err := state.ExportKeyingMaterial(label, nil, 10)
						assert.ErrorIs(t, err, tt.labelErr, label)
					}
				})
			}
		})
	}
}

func TestShouldWrapConnectionIDUsesOnlyDTLS12(t *testing.T) {
	state12 := dtlsstate.NewActive(false)
	assert.False(t, state12.ShouldWrapConnectionID())
	dtlsstate.CommonState(state12).RemoteConnectionID = []byte{0x01}
	assert.True(t, state12.ShouldWrapConnectionID())

	state13 := dtlsstate.NewState13(false)
	state13.RemoteConnectionID = []byte{0x01}
	assert.False(t, state13.ShouldWrapConnectionID())
}

func marshalVersionNegotiationHelloRetryRequestServerHello13(t *testing.T, cfg *dtlsconfig.HandshakeConfig, extensions []extension.Value) []byte {
	t.Helper()

	var hrrRandomFixed [handshake.RandomLength]byte
	copy(hrrRandomFixed[:], handshake.HelloRetryRequestRandom())
	var hrrRandom handshake.Random
	hrrRandom.UnmarshalFixed(hrrRandomFixed)

	return marshalVersionNegotiationServerHello13(t, cfg, hrrRandom, extensions)
}

func marshalVersionNegotiationServerHello13(t *testing.T, cfg *dtlsconfig.HandshakeConfig, random handshake.Random, extensions []extension.Value) []byte {
	t.Helper()

	cipherSuiteID := uint16(cfg.LocalCipherSuites[0].ID())
	serverHello := &handshake.MessageServerHello{Version: protocol.Version1_2, Random: random, CipherSuiteID: &cipherSuiteID, CompressionMethod: dtlsflight.DefaultCompressionMethods()[0], Extensions: extensions}
	rawServerHello, err := (&handshake.Handshake{Message: serverHello}).Marshal()
	assert.NoError(t, err)

	return rawServerHello
}

func testVersionNegotiationHandshakeConfig13(t *testing.T) *dtlsconfig.HandshakeConfig {
	t.Helper()

	cipherSuites, err := selectCipherSuites(
		nil,
		nil,
		true,
		false,
		protocol.Version1_3,
		protocol.Version1_3,
	)
	assert.NoError(t, err)

	loggerFactory := logging.NewDefaultLoggerFactory()

	return &dtlsconfig.HandshakeConfig{
		LocalCipherSuites:           cipherSuites,
		EllipticCurves:              defaultCurves,
		InitialRetransmitInterval:   time.Second,
		ExtendedMasterSecret:        dtlsconfig.ExtendedMasterSecretType(RequestExtendedMasterSecret),
		Log:                         loggerFactory.NewLogger("dtls"),
		MinVersion:                  protocol.Version1_3,
		MaxVersion:                  protocol.Version1_3,
		LocalSignatureSchemes:       signaturehash.Algorithms(),
		LocalCertSignatureSchemes:   nil,
		LocalSRTPProtectionProfiles: nil,
	}
}

func TestPickVersionFromServerHelloRejectsUnsolicitedExtension(t *testing.T) {
	const offeredType extension.Type = 0xfefe
	extensions := []extension.Value{
		extension.Raw{Type: offeredType, Data: []byte{0x01}},
	}
	clientHello := handshake.MessageClientHello{Version: protocol.Version1_2, CipherSuiteIDs: []uint16{0x1301}, CompressionMethods: []*protocol.CompressionMethod{{}}, Extensions: extensions}
	_, offer, err := negotiation.FinalizeClientHello(&clientHello, nil)
	require.NoError(t, err)

	cfg := testVersionNegotiationHandshakeConfig13(t)
	cfg.MinVersion = protocol.Version1_2
	common := &dtlsstate.Common{}
	require.NoError(t, common.LocalClientHelloSnapshots.Record(offer))
	conn := &Conn{
		handshakeConfig: cfg,
		state:           &dtlsstate.State13{Common: common},
	}
	extensions = []extension.Value{
		extension.Raw{Type: 0xfefd, Data: []byte{0x02}},
	}
	serverHello := handshake.MessageServerHello{
		Version:    protocol.Version1_2,
		Extensions: extensions,
	}
	err = conn.pickVersionFromServerHello(&serverHello)

	require.ErrorIs(t, err, dtlserrors.ErrUnsolicitedExtension)
	var classified *alert.Alert
	require.ErrorAs(t, err, &classified)
	assert.Equal(t, alert.UnsupportedExtension, classified.Description)
	assert.Equal(t, protocol.Version(0), common.LocalVersion)
}

func TestPickVersionFromServerResponseRejectsHelloRetryRequestWithoutSupportedVersions(t *testing.T) {
	cfg := testVersionNegotiationHandshakeConfig13(t)
	cfg.MinVersion = protocol.Version1_2
	cfg.MaxVersion = protocol.Version1_3
	selectedGroup := elliptic.P384

	rawServerHello := marshalVersionNegotiationHelloRetryRequestServerHello13(t, cfg, []extension.Value{&extension13.RetryKeyShare{SelectedGroup: selectedGroup}})

	conn := &Conn{
		handshakeCache:  dtlsflight.NewCache(),
		handshakeConfig: cfg,
	}
	conn.handshakeCache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	ok, err := conn.pickVersionFromServerResponse()

	assert.ErrorIs(t, err, dtlserrors.ErrMissingSupportedVersionsExtension)
	var classified *alert.Alert
	require.ErrorAs(t, err, &classified)
	assert.Equal(t, alert.MissingExtension, classified.Description)
	assert.False(t, ok)
	assert.Equal(t, protocol.Version(0), dtlsstate.CommonState(conn.state).LocalVersion)
}

func TestPickVersionFromServerResponseRejectsUnexpectedMessage(t *testing.T) {
	cfg := testVersionNegotiationHandshakeConfig13(t)
	cfg.MinVersion = protocol.Version1_2
	cfg.MaxVersion = protocol.Version1_3
	raw, err := (&handshake.Handshake{
		Message: &handshake.MessageFinished{VerifyData: []byte{0x01}},
	}).Marshal()
	require.NoError(t, err)

	conn := &Conn{
		handshakeCache:  dtlsflight.NewCache(),
		handshakeConfig: cfg,
	}
	conn.handshakeCache.Push(raw, cfg.InitialEpoch, 0, handshake.TypeFinished, false)

	ok, err := conn.pickVersionFromServerResponse()

	assert.ErrorIs(t, err, dtlserrors.ErrUnexpectedHandshakeMessage)
	var classified *alert.Alert
	require.ErrorAs(t, err, &classified)
	assert.Equal(t, alert.UnexpectedMessage, classified.Description)
	assert.False(t, ok)
}

func TestPickVersionFromServerResponsePreservesDecodeAlert(t *testing.T) {
	cfg := testVersionNegotiationHandshakeConfig13(t)
	cfg.MinVersion = protocol.Version1_2
	cfg.MaxVersion = protocol.Version1_3
	conn := &Conn{
		handshakeCache:  dtlsflight.NewCache(),
		handshakeConfig: cfg,
	}
	conn.handshakeCache.Push([]byte{byte(handshake.TypeServerHello)}, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	ok, err := conn.pickVersionFromServerResponse()

	assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)
	var classified *alert.Alert
	require.ErrorAs(t, err, &classified)
	assert.Equal(t, alert.DecodeError, classified.Description)
	assert.False(t, ok)
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
		[]extension.Value{
			extension.Raw{
				Type: extension.TypeSupportedVersions,
				Data: []byte{
					0x02,       // ClientHello vector length
					0xfe, 0xfc, // DTLS v1.3
				},
			},
		},
	)

	parsed := &handshake.Handshake{}
	err := parsed.Unmarshal(rawServerHello)
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidSupportedVersionsFormat)
}

func TestSelectRemoteVersionActivatesChosenState(t *testing.T) {
	cfg := testVersionNegotiationHandshakeConfig13(t)
	cfg.MinVersion = protocol.Version1_2
	cfg.MaxVersion = protocol.Version1_3

	commonState := &dtlsstate.Common{}
	conn := &Conn{
		handshakeConfig: cfg,
		state: &dtlsstate.State12{
			Common:                commonState,
			HandshakeSendSequence: 3,
		},
	}
	err := conn.selectRemoteVersion([]protocol.Version{protocol.Version1_3})
	assert.NoError(t, err)
	state13, ok := conn.state.(*dtlsstate.State13)
	assert.True(t, ok)
	assert.Equal(t, 3, state13.HandshakeSendSequence)
	assert.NotNil(t, state13.LocalKeypairs)
	assert.Equal(t, protocol.Version1_3, dtlsstate.CommonState(conn.state).LocalVersion)

	err = conn.selectRemoteVersion([]protocol.Version{protocol.Version1_2})
	assert.NoError(t, err)
	state12, ok := conn.state.(*dtlsstate.State12)
	assert.True(t, ok)
	assert.Equal(t, 3, state12.HandshakeSendSequence)
	assert.Equal(t, protocol.Version1_2, dtlsstate.CommonState(conn.state).LocalVersion)
}

type connWithCallback struct {
	*packetTestConn
	onWrite func([]byte)
}

func (c *connWithCallback) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.onWrite != nil {
		c.onWrite(b)
	}

	return c.packetTestConn.WriteTo(b, addr)
}

func TestPacketQueueWriterCopiesExactRecord(t *testing.T) {
	readBuffer := []byte{1, 2, 3}
	conn := &Conn{}
	lease := readBufferLease{
		conn:                 conn,
		recyclableReadBuffer: &readBuffer,
		datagramContainsCID:  true,
	}

	require.True(t, lease.enqueue(addrPkt{data: readBuffer}))
	assert.Same(t, &readBuffer, lease.recyclableReadBuffer)
	require.Len(t, conn.encryptedPackets, 1)
	assert.NotSame(t, &readBuffer[0], &conn.encryptedPackets[0].data[0])
	assert.Equal(t, len(conn.encryptedPackets[0].data), cap(conn.encryptedPackets[0].data))
	assert.True(t, conn.encryptedPackets[0].datagramContainsCID)
	readBuffer[0] = 9
	assert.Equal(t, []byte{1, 2, 3}, conn.encryptedPackets[0].data)

	rejectedReadBuffer := []byte{4, 5, 6}
	fullConn := &Conn{encryptedPackets: make([]addrPkt, maxAppDataPacketQueueSize)}
	rejectedLease := readBufferLease{conn: fullConn, recyclableReadBuffer: &rejectedReadBuffer}
	assert.False(t, rejectedLease.enqueue(addrPkt{data: rejectedReadBuffer}))
	assert.Same(t, &rejectedReadBuffer, rejectedLease.recyclableReadBuffer)
}

func TestReadAndBufferNoFSMQueuesExactRecordCopy(t *testing.T) {
	ca, cb := packetPipe()
	defer func() {
		assert.NoError(t, ca.Close())
		assert.NoError(t, cb.Close())
	}()

	conn := &Conn{
		nextConn:       netctx.NewPacketConn(cb),
		fragmentBuffer: dtlsfragmentbuffer.New(),
		handshakeCache: dtlsflight.NewCache(),
		readBufferPool: readBufferPoolForSize(defaultReceiveBufferSize),
		log:            logging.NewDefaultLoggerFactory().NewLogger("dtls"),
		state: &dtlsstate.State13{Common: &dtlsstate.Common{
			LocalVersion: protocol.Version1_3,
		}},
	}
	rawPacket, err := recordlayer.MarshalCiphertext(recordlayer.CiphertextConfig{EpochLow: uint8(dtlsflight13.EpochHandshake), SequenceNumber: 1, TwoByteSequence: true, LengthPresent: true}, bytes.Repeat([]byte{0xa5}, 16))
	require.NoError(t, err)

	writeResult := make(chan error, 1)
	go func() {
		_, writeErr := ca.Write(rawPacket)
		writeResult <- writeErr
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, conn.readAndBufferNoFSM(ctx))
	require.NoError(t, <-writeResult)
	require.Len(t, conn.encryptedPackets, 1)
	assert.Equal(t, rawPacket, conn.encryptedPackets[0].data)
	assert.Equal(t, len(rawPacket), cap(conn.encryptedPackets[0].data))
}

func TestHandleIncomingPacket13RejectsFixedHandshakeEpoch(t *testing.T) {
	commonState := &dtlsstate.Common{IsClient: true, LocalVersion: protocol.Version1_3}
	conn := &Conn{
		fragmentBuffer:         dtlsfragmentbuffer.New(),
		handshakeCache:         dtlsflight.NewCache(),
		log:                    logging.NewDefaultLoggerFactory().NewLogger("dtls"),
		replayProtectionWindow: defaultReplayProtectionWindow,
		handshakeConfig:        testVersionNegotiationHandshakeConfig13(t),
		state:                  &dtlsstate.State13{Common: commonState},
	}
	conn.setRemoteEpoch(0)

	rawPacket, err := marshalTestRecord(recordlayer.RecordConfig{Version: protocol.Version1_2, Epoch: uint16(dtlsflight13.EpochHandshake), SequenceNumber: 0}, &handshake.Handshake{Header: handshake.Header{MessageSequence: 1}, Message: &handshake.MessageEncryptedExtensions{}})
	assert.NoError(t, err)

	bufferLease := &readBufferLease{conn: conn, recyclableReadBuffer: &rawPacket}
	outcome, err := conn.handleIncomingPacket(
		context.Background(),
		rawPacket,
		nil,
		bufferLease,
		false,
	)
	assert.NoError(t, err)
	assert.Nil(t, outcome.responseAlert)
	assert.False(t, outcome.containsHandshake)
	assert.False(t, outcome.retransmit)
	assert.Same(t, &rawPacket, bufferLease.recyclableReadBuffer)
	assert.Empty(t, conn.encryptedPackets)
}

func TestOnConnectionAttemptConnectionOwnership(t *testing.T) {
	expectedErr := errors.New("connection rejected") //nolint:err113
	config, err := buildServerConfig(WithOnConnectionAttempt(func(net.Addr) error { return expectedErr }))
	assert.NoError(t, err)

	t.Run("Listener closes rejected accepted PacketConn", func(t *testing.T) {
		ca, cb := packetPipe()
		defer func() {
			assert.NoError(t, ca.Close())
		}()

		conn := &closeTrackingPacketConn{PacketConn: cb}
		l := &listener{
			config: config,
			parent: &singlePacketListener{conn: conn, raddr: cb.RemoteAddr()},
		}

		_, err := l.Accept()
		assert.ErrorIs(t, err, expectedErr)
		assert.True(t, conn.closed.Load())
	})
}

type closeTrackingPacketConn struct {
	net.PacketConn
	closed atomic.Bool
}

func (c *closeTrackingPacketConn) Close() error {
	c.closed.Store(true)

	return c.PacketConn.Close()
}

type singlePacketListener struct {
	conn  net.PacketConn
	raddr net.Addr
}

func (l *singlePacketListener) Accept() (net.PacketConn, net.Addr, error) {
	return l.conn, l.raddr, nil
}

func (*singlePacketListener) Close() error { return nil }

func (*singlePacketListener) Addr() net.Addr { return nil }

func TestFragmentBuffer_Retransmission(t *testing.T) {
	fragmentBuffer := dtlsfragmentbuffer.New()
	frag := []byte{0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x30, 0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff, 0x01, 0x01}

	result, err := fragmentBuffer.Push(0, frag[recordlayer.FixedHeaderSize:])
	assert.NoError(t, err)
	assert.False(t, result.IsRetransmit)

	v, _ := fragmentBuffer.Pop()
	assert.NotNil(t, v)

	result, err = fragmentBuffer.Push(0, frag[recordlayer.FixedHeaderSize:])
	assert.NoError(t, err)
	assert.True(t, result.IsRetransmit)
}

func TestDTLS13ServerSendsFinalACK(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(10 * time.Second).Stop()

	ca, cb := packetPipe()
	var applicationEpochWrites atomic.Int32
	ackRecord := make(chan []byte, 1)
	serverTransport := &connWithCallback{
		packetTestConn: cb,
		onWrite: func(raw []byte) {
			if len(raw) > 0 && protocol.IsDTLS13Ciphertext(protocol.ContentType(raw[0])) && raw[0]&recordwire.EpochMask == byte(dtlsflight13.EpochApplication) {
				applicationEpochWrites.Add(1)
				select {
				case ackRecord <- append([]byte(nil), raw...):
				default:
				}
			}
		},
	}

	clientCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	client, err := Client(ca, ca.RemoteAddr(), WithCertificates(clientCert), WithInsecureSkipVerify(true), WithMinVersion(protocol.Version1_3), WithMaxVersion(protocol.Version1_3))
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	serverCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	server, err := Server(serverTransport, serverTransport.RemoteAddr(), WithCertificates(serverCert), WithInsecureSkipVerify(true), WithMinVersion(protocol.Version1_3), WithMaxVersion(protocol.Version1_3))
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errs := make(chan error, 2)
	go func() { errs <- client.HandshakeContext(ctx) }()
	go func() { errs <- server.HandshakeContext(ctx) }()
	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	assert.GreaterOrEqual(t, applicationEpochWrites.Load(), int32(1))

	var rawACK []byte
	select {
	case rawACK = <-ackRecord:
	case <-time.After(time.Second):
		require.FailNow(t, "server did not write an application-epoch ACK")
	}
	ciphertext := unmarshalCiphertextRecordForTest(t, rawACK, 0)
	clientState, ok := client.state.(*dtlsstate.State13)
	require.True(t, ok)
	readGeneration, ok := clientState.TrafficKeys.Read(dtlsflight13.EpochApplication)
	require.True(t, ok)
	protection := &testRecordProtection13{TrafficProtection: readGeneration.Protection, capabilities: clientState.CipherSuite.Capabilities()}
	innerPlaintext, err := protection.OpenRecord(ciphertext.Header, 0, ciphertext.EncryptedRecord)
	require.NoError(t, err)
	require.Equal(t, protocol.ContentTypeACK, innerPlaintext.RealType)
	var ack protocol.ACK
	require.NoError(t, ack.Unmarshal(innerPlaintext.Content))
	require.NotEmpty(t, ack.Records)
	assert.Equal(t, dtlsflight13.EpochHandshake, ack.Records[0].Epoch)
}

func TestHandshakeCancellationWhilePostSetupBlocks(t *testing.T) {
	defer test.CheckRoutines(t)()

	ca, cb := packetPipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	clientCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	client, err := Client(ca, ca.RemoteAddr(), WithCertificates(clientCert), WithInsecureSkipVerify(true), WithMinVersion(protocol.Version1_3), WithMaxVersion(protocol.Version1_3))
	require.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	postSetupStarted := make(chan struct{})
	start := client.prepareHandshakeStart13()
	start.fsmState = dtlshandshake.StateWaiting
	start.postSetup = func(ctx context.Context) {
		close(postSetupStarted)
		<-ctx.Done()
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- client.handshake(ctx, start)
	}()

	select {
	case <-postSetupStarted:
	case <-time.After(time.Second):
		require.FailNow(t, "post-setup hook did not start")
	}
	cancel()

	select {
	case err = <-result:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		require.FailNow(t, "handshake did not observe context cancellation")
	}
}

func TestProcessProtectedPacketWritesDTLS13HandshakeRecord(t *testing.T) {
	conn, peerCipherSuite := newTestConnWithWriteProtection(t)
	dtlsHandshake := &handshake.Handshake{
		Message: &handshake.MessageEncryptedExtensions{},
	}
	expectedPlaintext, err := dtlsHandshake.Marshal()
	assert.NoError(t, err)

	rawPacket, err := conn.prepareRecord(&dtlsflight.Outbound{Epoch: dtlsflight13.EpochHandshake, Content: dtlsHandshake, Protection: dtlsflight.ProtectionCiphertext})
	assert.NoError(t, err)
	assert.NotEmpty(t, rawPacket)
	assert.True(t, protocol.IsDTLS13Ciphertext(protocol.ContentType(rawPacket[0])))

	innerPlaintext := openTestProtectedRecord(t, peerCipherSuite, rawPacket)
	assert.Equal(t, protocol.ContentTypeHandshake, innerPlaintext.RealType)
	assert.Equal(t, expectedPlaintext, innerPlaintext.Content)
}

type sequenceRecordingProtection struct {
	capabilities cryptosuite.Capabilities
	sequences    []uint64
}

func (p *sequenceRecordingProtection) Seal(record cryptosuite.Record, plaintext []byte) ([]byte, error) {
	p.sequences = append(p.sequences, record.RecordNumber()&recordlayer.MaxSequenceNumber)
	protectedLen, err := p.capabilities.ProtectedLen(len(plaintext))
	if err != nil {
		return nil, err
	}

	return make([]byte, protectedLen), nil
}

func (*sequenceRecordingProtection) Open(cryptosuite.Record, []byte) ([]byte, error) {
	return nil, cryptosuite.ErrAuthenticationFailed
}

func TestProcessHandshakePacketCIDFragmentsUseAllocatedSequenceNumbers(t *testing.T) {
	const (
		epoch                = 1
		firstSequence uint64 = 41
		staleSequence uint64 = 7
	)

	remoteCID := []byte("remote-cid")
	cipherSuite := ciphersuite.ForID(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	protection := &sequenceRecordingProtection{capabilities: cipherSuite.Capabilities()}
	commonState := &dtlsstate.Common{LocalVersion: protocol.Version1_2, LocalSequenceNumber: map[uint64]uint64{1: firstSequence}, RemoteConnectionID: remoteCID, CipherSuite: cipherSuite}
	conn := &Conn{maximumTransmissionUnit: 10, paddingLengthGenerator: func(uint) uint { return 0 }, state: &dtlsstate.State12{Common: commonState, Protection: protection}}
	dtlsHandshake := &handshake.Handshake{Header: handshake.Header{MessageSequence: 9}, Message: &handshake.MessageCertificate{Certificate: [][]byte{bytes.Repeat([]byte{0xaa}, 24)}}}
	_, err := dtlsHandshake.Marshal()
	require.NoError(t, err)

	pkt := &dtlsflight.Outbound{
		Epoch:      epoch,
		Content:    dtlsHandshake,
		Protection: dtlsflight.ProtectionCiphertext,
	}
	prepared, err := conn.prepareHandshakeRecords(pkt, dtlsHandshake)
	require.NoError(t, err)
	require.Greater(t, len(prepared), 1)

	expectedSequences := make([]uint64, len(prepared))
	for i, record := range prepared {
		expectedSequence := firstSequence + uint64(i)
		expectedSequences[i] = expectedSequence

		header, parseErr := recordlayer.ParseRecord(record.raw, len(remoteCID))
		require.NoError(t, parseErr)
		assert.Equal(t, protocol.ContentTypeConnectionID, header.ContentType())
		assert.Equal(t, remoteCID, header.ConnectionID())
		assert.Equal(t, uint16(epoch), header.Epoch())
		assert.Equal(t, expectedSequence, header.SequenceNumber())
	}

	// Encrypt receives this record metadata for the nonce and MAC calculation.
	assert.Equal(t, expectedSequences, protection.sequences)
	assert.Equal(t, firstSequence+uint64(len(expectedSequences)), commonState.LocalSequenceNumber[epoch])
}

func TestProcessProtectedHandshakePacketWritesDTLS13Fragments(t *testing.T) {
	conn, peerCipherSuite := newTestConnWithWriteProtection(t)
	dtlsHandshake := &handshake.Handshake{
		Message: &handshake.MessageEncryptedExtensions{},
	}
	expectedPlaintext, err := dtlsHandshake.Marshal()
	assert.NoError(t, err)

	prepared, err := conn.prepareHandshakeRecords(&dtlsflight.Outbound{Epoch: dtlsflight13.EpochHandshake, Content: dtlsHandshake, Protection: dtlsflight.ProtectionCiphertext}, dtlsHandshake)
	assert.NoError(t, err)
	require.Len(t, prepared, 1)
	assert.True(t, protocol.IsDTLS13Ciphertext(protocol.ContentType(prepared[0].raw[0])))

	innerPlaintext := openTestProtectedRecord(t, peerCipherSuite, prepared[0].raw)
	assert.Equal(t, protocol.ContentTypeHandshake, innerPlaintext.RealType)
	assert.Equal(t, expectedPlaintext, innerPlaintext.Content)
}

func TestProcessProtectedHandshakePacketFiltersACKedFragments(t *testing.T) {
	conn, _ := newTestConnWithWriteProtection(t)
	conn.maximumTransmissionUnit = 10
	dtlsHandshake := &handshake.Handshake{Header: handshake.Header{MessageSequence: 9}, Message: &handshake.MessageCertificate{Certificate: [][]byte{bytes.Repeat([]byte{0xaa}, 24)}}}
	_, err := dtlsHandshake.Marshal()
	require.NoError(t, err)

	prepared, err := conn.prepareHandshakeRecords(&dtlsflight.Outbound{Epoch: dtlsflight13.EpochHandshake, Content: dtlsHandshake, Protection: dtlsflight.ProtectionCiphertext, TrackACK: true, HandshakeFragmentOffsets: map[uint32]uint32{10: 10}}, dtlsHandshake)
	require.NoError(t, err)
	require.Len(t, prepared, 1)
	assert.Equal(t, uint32(10), prepared[0].tracked.Fragments[0].Offset)
}

func TestProcessProtectedPacketWritesApplicationData(t *testing.T) {
	conn, peerCipherSuite := newTestConnWithWriteProtection(t)
	payload := []byte("application data")

	rawPacket, err := conn.prepareRecord(&dtlsflight.Outbound{Epoch: dtlsflight13.EpochApplication, Content: &protocol.ApplicationData{Data: payload}, Protection: dtlsflight.ProtectionCiphertext})
	require.NoError(t, err)

	innerPlaintext := openTestProtectedRecord(t, peerCipherSuite, rawPacket)
	assert.Equal(t, protocol.ContentTypeApplicationData, innerPlaintext.RealType)
	assert.Equal(t, payload, innerPlaintext.Content)
}

func TestProcessProtectedPacketWritesACK(t *testing.T) {
	conn, peerCipherSuite := newTestConnWithWriteProtection(t)
	ack := &protocol.ACK{Records: []protocol.RecordNumber{{Epoch: 2, SequenceNumber: 9}}}
	expected, err := ack.Marshal()
	require.NoError(t, err)

	rawPacket, err := conn.prepareRecord(&dtlsflight.Outbound{Epoch: dtlsflight13.EpochApplication, Content: ack, Protection: dtlsflight.ProtectionCiphertext})
	require.NoError(t, err)
	innerPlaintext := openTestProtectedRecord(t, peerCipherSuite, rawPacket)
	assert.Equal(t, protocol.ContentTypeACK, innerPlaintext.RealType)
	assert.Equal(t, expected, innerPlaintext.Content)
}

func TestOpenCiphertextRecordHandshake(t *testing.T) {
	conn, peerCipherSuite := newTestConnWithReadProtection(t)
	expectedPlaintext := encryptedExtensionsHandshake(t)
	record := sealTestProtectedHandshakeRecord(t, peerCipherSuite, expectedPlaintext)

	innerPlaintext, sequenceNumber, epoch, err := conn.openCiphertextRecord(record.parsed(t))
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), sequenceNumber)
	assert.Equal(t, dtlsflight13.EpochHandshake, epoch)
	assert.Equal(t, protocol.ContentTypeHandshake, innerPlaintext.RealType)
	assert.Equal(t, expectedPlaintext, innerPlaintext.Content)
}

func TestOpenCiphertextRecordRejectsInvalidRecords(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Conn, *sealedTestRecord)
		wantErr error
	}{
		{
			name: "wrong sequence number",
			mutate: func(conn *Conn, _ *sealedTestRecord) {
				dtlsstate.CommonState(conn.state).UpdateRemoteSequenceNumber(dtlsflight13.EpochHandshake, 0xffff)
			},
			wantErr: errRecordAuthentication,
		},
		{name: "wrong epoch", mutate: func(_ *Conn, record *sealedTestRecord) { record.Header.EpochLow ^= 0x01 }, wantErr: dtlserrors.ErrInvalidEpoch},
		{name: "tampered ciphertext", mutate: func(_ *Conn, record *sealedTestRecord) { record.EncryptedRecord[0] ^= 0x80 }, wantErr: errRecordAuthentication},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn, peerCipherSuite := newTestConnWithReadProtection(t)
			record := sealTestProtectedHandshakeRecord(t, peerCipherSuite, encryptedExtensionsHandshake(t))
			test.mutate(conn, &record)

			innerPlaintext, sequenceNumber, epoch, err := conn.openCiphertextRecord(record.parsed(t))
			assert.ErrorIs(t, err, test.wantErr)
			assert.Zero(t, innerPlaintext)
			assert.Zero(t, sequenceNumber)
			assert.Zero(t, epoch)
		})
	}
}

func TestDTLS13DecryptedEncryptedExtensionsIsCached(t *testing.T) {
	conn, peerCipherSuite := newTestConnWithReadProtection(t)
	state13, err := dtlsstate.As13(conn.state)
	require.NoError(t, err)
	state13.HandshakeRecvSequence = 1
	expectedPlaintext := encryptedExtensionsHandshakeWithSequence(t, 1)
	record := sealTestProtectedHandshakeRecord(t, peerCipherSuite, expectedPlaintext)
	rawPacket, err := record.Marshal()
	assert.NoError(t, err)

	bufferLease := &readBufferLease{conn: conn}
	outcome, err := conn.handleIncomingPacket(
		context.Background(), rawPacket, nil, bufferLease, false,
	)
	assert.NoError(t, err)
	assert.Nil(t, outcome.responseAlert)
	assert.True(t, outcome.containsHandshake)
	assert.False(t, outcome.retransmit)

	items := conn.handshakeCache.Pull(dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeEncryptedExtensions, Epoch: dtlsflight13.EpochHandshake, IsClient: false})
	if assert.Len(t, items, 1) && assert.NotNil(t, items[0]) {
		assert.Equal(t, dtlsflight13.EpochHandshake, items[0].Epoch)
		assert.Equal(t, uint16(1), items[0].MessageSequence)
		assert.Equal(t, expectedPlaintext, items[0].Data)
	}
}

func TestDTLS13ProtectedHandshakeRecordKeepsEpochAndSequence(t *testing.T) {
	conn, peerCipherSuite := newTestConnWithReadProtection(t)
	const sequenceNumber = uint64(0x1002a)
	dtlsstate.CommonState(conn.state).UpdateRemoteSequenceNumber(dtlsflight13.EpochHandshake, 0x10005)
	expectedPlaintext := encryptedExtensionsHandshakeWithSequence(t, 0)
	record := sealTestProtectedHandshakeRecordWithSequence(t, peerCipherSuite, expectedPlaintext, sequenceNumber)
	rawPacket, err := record.Marshal()
	assert.NoError(t, err)

	prepared, ok, err := conn.prepareIncomingPacket(rawPacket, nil, &readBufferLease{conn: conn}, false)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, dtlsflight13.EpochHandshake, prepared.number.Epoch)
	assert.Equal(t, sequenceNumber, prepared.number.SequenceNumber)
	assert.Equal(t, protocol.ContentTypeHandshake, prepared.contentType)
	assert.Equal(t, expectedPlaintext, prepared.content)
	assert.Equal(t, rawPacket, prepared.raw)
}

type testRecordProtection13 struct {
	cryptosuite.TrafficProtection
	capabilities cryptosuite.Capabilities
}

func newTestRecordProtection13(
	suite cryptosuite.TrafficSuite,
	secret []byte,
) (*testRecordProtection13, error) {
	trafficSecret, err := ciphersuite.NewTrafficSecret(secret)
	if err != nil {
		return nil, err
	}
	protection, err := suite.NewTrafficProtection(trafficSecret)
	if err != nil {
		return nil, err
	}

	return &testRecordProtection13{TrafficProtection: protection, capabilities: suite.Capabilities()}, nil
}

func (p *testRecordProtection13) SealRecord(header recordlayer.CiphertextConfig, sequenceNumber uint64, contentType protocol.ContentType, plaintext []byte) (sealedTestRecord, error) {
	innerPlaintext, err := recordlayer.MarshalInnerPlaintext(plaintext, contentType, 0)
	if err != nil {
		return sealedTestRecord{}, err
	}
	protectedLen, err := p.capabilities.ProtectedLen(len(innerPlaintext))
	if err != nil {
		return sealedTestRecord{}, err
	}
	header, metadata, err := newTestRecord13(header, sequenceNumber, protectedLen)
	if err != nil {
		return sealedTestRecord{}, err
	}
	protected, err := p.Seal(metadata, innerPlaintext)
	if err != nil {
		return sealedTestRecord{}, err
	}
	mask, err := p.sequenceNumberMask(protected)
	if err != nil {
		return sealedTestRecord{}, err
	}
	header.SequenceNumber, err = applySequenceNumberMask(header.SequenceNumber, true, mask)
	if err != nil {
		return sealedTestRecord{}, err
	}

	return sealedTestRecord{Header: header, EncryptedRecord: protected}, nil
}

func (p *testRecordProtection13) OpenRecord(header recordlayer.CiphertextConfig, sequenceNumber uint64, protected []byte) (openedRecord, error) {
	mask, err := p.sequenceNumberMask(protected)
	if err != nil {
		return openedRecord{}, err
	}
	header.SequenceNumber, err = applySequenceNumberMask(header.SequenceNumber, header.TwoByteSequence, mask)
	if err != nil {
		return openedRecord{}, err
	}
	clearHeader, err := recordwire.AppendUnifiedHeader(nil, header.EpochLow, header.SequenceNumber, header.TwoByteSequence, header.ConnectionID, header.LengthPresent, len(protected))
	if err != nil {
		return openedRecord{}, err
	}
	metadata, err := ciphersuite.NewUnifiedRecord(uint64(header.EpochLow), sequenceNumber, clearHeader, len(protected))
	if err != nil {
		return openedRecord{}, err
	}
	plaintext, err := p.Open(metadata, protected)
	if errors.Is(err, cryptosuite.ErrAuthenticationFailed) {
		return openedRecord{}, dtlserrors.ErrDecryptPacket
	}
	if err != nil {
		return openedRecord{}, err
	}
	content, realType, _, err := recordlayer.ParseInnerPlaintext(plaintext)
	innerPlaintext := openedRecord{Content: content, RealType: realType}
	if err != nil {
		return openedRecord{}, err
	}

	return innerPlaintext, nil
}

func newTestRecord13(header recordlayer.CiphertextConfig, sequenceNumber uint64, protectedLen int) (recordlayer.CiphertextConfig, cryptosuite.Record, error) {
	header.SequenceNumber = uint16(sequenceNumber) //nolint:gosec
	header.TwoByteSequence = true
	header.LengthPresent = true
	clearHeader, err := recordwire.AppendUnifiedHeader(nil, header.EpochLow, header.SequenceNumber, header.TwoByteSequence, header.ConnectionID, header.LengthPresent, protectedLen)
	if err != nil {
		return header, nil, err
	}
	metadata, err := ciphersuite.NewUnifiedRecord(uint64(header.EpochLow), sequenceNumber, clearHeader, protectedLen)

	return header, metadata, err
}

func (p *testRecordProtection13) sequenceNumberMask(protected []byte) ([]byte, error) {
	maskLen := p.capabilities.MaskLen()
	if len(protected) < maskLen {
		return nil, dtlserrors.ErrBufferTooSmall
	}

	return p.Mask(protected[:maskLen])
}

func newTestConnWithWriteProtection(t *testing.T) (*Conn, *testRecordProtection13) {
	t.Helper()

	localCipherSuite := trafficSuiteForTest(t)
	clientSecret := bytes.Repeat([]byte{0x11}, localCipherSuite.HashFunc()().Size())
	serverSecret := bytes.Repeat([]byte{0x22}, localCipherSuite.HashFunc()().Size())
	localWriteProtection, err := newTestRecordProtection13(localCipherSuite, clientSecret)
	assert.NoError(t, err)
	localReadProtection, err := newTestRecordProtection13(localCipherSuite, serverSecret)
	assert.NoError(t, err)

	peerCipherSuite := trafficSuiteForTest(t)
	peerReadProtection, err := newTestRecordProtection13(peerCipherSuite, clientSecret)
	assert.NoError(t, err)

	commonState := &dtlsstate.Common{
		IsClient:     true,
		LocalVersion: protocol.Version1_3,
		CipherSuite:  localCipherSuite,
	}
	state13 := &dtlsstate.State13{Common: commonState, TrafficKeys: &dtlsstate.TrafficKeyState{}}
	state13.TrafficKeys.Install(&dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochHandshake, Secret: clientSecret, Protection: localWriteProtection}, &dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochHandshake, Secret: serverSecret, Protection: localReadProtection})
	state13.TrafficKeys.Install(&dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochApplication, Secret: clientSecret, Protection: localWriteProtection}, &dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochApplication, Secret: serverSecret, Protection: localReadProtection})

	return &Conn{handshakeCache: dtlsflight.NewCache(), maximumTransmissionUnit: defaultMTU, state: state13}, peerReadProtection
}

func newTestConnWithReadProtection(t *testing.T) (*Conn, *testRecordProtection13) {
	t.Helper()

	localCipherSuite := trafficSuiteForTest(t)
	clientSecret := bytes.Repeat([]byte{0x11}, localCipherSuite.HashFunc()().Size())
	serverSecret := bytes.Repeat([]byte{0x22}, localCipherSuite.HashFunc()().Size())
	localWriteProtection, err := newTestRecordProtection13(localCipherSuite, clientSecret)
	assert.NoError(t, err)
	localReadProtection, err := newTestRecordProtection13(localCipherSuite, serverSecret)
	assert.NoError(t, err)

	peerCipherSuite := trafficSuiteForTest(t)
	peerWriteProtection, err := newTestRecordProtection13(peerCipherSuite, serverSecret)
	assert.NoError(t, err)

	commonState := &dtlsstate.Common{
		IsClient:     true,
		LocalVersion: protocol.Version1_3,
		CipherSuite:  localCipherSuite,
	}
	state13 := &dtlsstate.State13{Common: commonState, TrafficKeys: &dtlsstate.TrafficKeyState{}}
	state13.TrafficKeys.Install(&dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochHandshake, Secret: clientSecret, Protection: localWriteProtection}, &dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochHandshake, Secret: serverSecret, Protection: localReadProtection})
	state13.TrafficKeys.Install(&dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochApplication, Secret: clientSecret, Protection: localWriteProtection}, &dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochApplication, Secret: serverSecret, Protection: localReadProtection})

	conn := &Conn{fragmentBuffer: dtlsfragmentbuffer.New(), handshakeCache: dtlsflight.NewCache(), maximumTransmissionUnit: defaultMTU, replayProtectionWindow: defaultReplayProtectionWindow, log: logging.NewDefaultLoggerFactory().NewLogger("dtls"), state: state13}
	conn.setRemoteEpoch(dtlsflight13.EpochHandshake)

	return conn, peerWriteProtection
}

func encryptedExtensionsHandshake(t *testing.T) []byte {
	t.Helper()

	return encryptedExtensionsHandshakeWithSequence(t, 0)
}

func encryptedExtensionsHandshakeWithSequence(t *testing.T, messageSequence uint16) []byte {
	t.Helper()

	raw, err := (&handshake.Handshake{Header: handshake.Header{MessageSequence: messageSequence}, Message: &handshake.MessageEncryptedExtensions{}}).Marshal()
	assert.NoError(t, err)

	return raw
}

func sealTestProtectedHandshakeRecord(t *testing.T, protection *testRecordProtection13, plaintext []byte) sealedTestRecord {
	t.Helper()

	return sealTestProtectedHandshakeRecordWithSequence(t, protection, plaintext, 0)
}

func sealTestProtectedHandshakeRecordWithSequence(t *testing.T, protection *testRecordProtection13, plaintext []byte, sequenceNumber uint64) sealedTestRecord {
	t.Helper()

	record, err := protection.SealRecord(recordlayer.CiphertextConfig{EpochLow: uint8(dtlsflight13.EpochHandshake & recordwire.EpochMask)}, sequenceNumber, protocol.ContentTypeHandshake, plaintext)
	assert.NoError(t, err)

	return record
}

func openTestProtectedRecord(t *testing.T, protection *testRecordProtection13, rawPacket []byte) openedRecord {
	t.Helper()

	ciphertext := unmarshalCiphertextRecordForTest(t, rawPacket, 0)

	innerPlaintext, err := protection.OpenRecord(
		ciphertext.Header,
		0,
		ciphertext.EncryptedRecord,
	)
	assert.NoError(t, err)

	return innerPlaintext
}

func unmarshalCiphertextRecordForTest(
	t *testing.T,
	raw []byte,
	cidLength int,
) sealedTestRecord {
	t.Helper()

	records, err := recordlayer.UnpackDatagram(raw, recordlayer.UnpackDatagramConfig{TargetVersion: protocol.Version1_3, CIDLength: cidLength})
	require.NoError(t, err)
	require.Len(t, records, 1)

	parsed, err := recordlayer.ParseRecord(records[0], cidLength)
	require.NoError(t, err)
	record := sealedTestRecord{Header: recordlayer.CiphertextConfig{EpochLow: parsed.EpochLow(), SequenceNumber: uint16(parsed.SequenceNumber() & 0xffff), TwoByteSequence: parsed.SequenceBytes() == 2, ConnectionID: parsed.ConnectionID(), LengthPresent: parsed.LengthPresent()}, EncryptedRecord: parsed.Payload()}

	return record
}

func TestSealRecordContentUsesWriteTrafficGeneration(t *testing.T) {
	conn, state, suite := newTrafficKeyTestConn(t)
	handshakeSecret := trafficKeyTestSecret(suite, 0x11)
	applicationSecret := trafficKeyTestSecret(suite, 0x22)
	handshakeProtection := trafficKeyTestProtection(t, suite, handshakeSecret)
	applicationProtection := trafficKeyTestProtection(t, suite, applicationSecret)

	state.TrafficKeys.Install(&dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochHandshake, Secret: handshakeSecret, Protection: handshakeProtection}, nil)
	state.TrafficKeys.Install(&dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochApplication, Secret: applicationSecret, Protection: applicationProtection}, nil)

	applicationRecord, err := conn.sealRecordContent(dtlsflight13.EpochApplication, 0, protocol.ContentTypeApplicationData, []byte("application"))
	require.NoError(t, err)
	assertTrafficKeyTestRecord(t, applicationProtection, applicationRecord, []byte("application"))

	handshakeRecord, err := conn.sealRecordContent(dtlsflight13.EpochHandshake, 0, protocol.ContentTypeHandshake, []byte("handshake"))
	require.NoError(t, err)
	assertTrafficKeyTestRecord(t, handshakeProtection, handshakeRecord, []byte("handshake"))

	_, err = conn.sealRecordContent(4, 0, protocol.ContentTypeApplicationData, nil)
	assert.ErrorIs(t, err, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented)
}

func TestSealRecordContentAcceptsMaximumContent(t *testing.T) {
	conn, peerProtection := newTestConnWithWriteProtection(t)
	plaintext := bytes.Repeat([]byte{0x5a}, maxPlaintextRecordLen)

	rawRecord, err := conn.sealRecordContent(dtlsflight13.EpochApplication, 0, protocol.ContentTypeApplicationData, plaintext)
	require.NoError(t, err)
	innerPlaintext := openTestProtectedRecord(t, peerProtection, rawRecord)
	assert.Equal(t, plaintext, innerPlaintext.Content)
}

func TestSealRecordContentUsesNegotiatedConnectionID(t *testing.T) {
	conn, state, suite := newTrafficKeyTestConn(t)
	secret := trafficKeyTestSecret(suite, 0x23)
	protection := trafficKeyTestProtection(t, suite, secret)
	state.TrafficKeys.Install(&dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochApplication, Secret: secret, Protection: protection}, nil)
	state.CommitNegotiatedExtensions(&negotiation.ConnectionID{ClientCID: []byte("local-cid"), ServerCID: []byte("remote-cid")})

	rawRecord, err := conn.sealRecordContent(dtlsflight13.EpochApplication, 0, protocol.ContentTypeApplicationData, []byte("application"))
	require.NoError(t, err)

	record := unmarshalCiphertextRecordForTest(t, rawRecord, len("remote-cid"))
	assert.Equal(t, []byte("remote-cid"), record.Header.ConnectionID)
	innerPlaintext, err := protection.OpenRecord(record.Header, 0, record.EncryptedRecord)
	require.NoError(t, err)
	assert.Equal(t, []byte("application"), innerPlaintext.Content)
}

func TestOpenCiphertextRecordUsesNegotiatedConnectionID(t *testing.T) {
	conn, state, suite := newTrafficKeyTestConn(t)
	secret := trafficKeyTestSecret(suite, 0x34)
	protection := trafficKeyTestProtection(t, suite, secret)
	state.TrafficKeys.Install(nil, &dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochApplication, Secret: secret, Protection: protection})
	state.SetRemoteEpoch(dtlsflight13.EpochApplication)
	state.CommitNegotiatedExtensions(&negotiation.ConnectionID{ClientCID: []byte("local-cid"), ServerCID: []byte("remote-cid")})

	sealed, err := protection.SealRecord(recordlayer.CiphertextConfig{ConnectionID: []byte("local-cid"), EpochLow: uint8(dtlsflight13.EpochApplication & recordwire.EpochMask)}, 0, protocol.ContentTypeApplicationData, []byte("application"))
	require.NoError(t, err)
	rawRecord, err := sealed.Marshal()
	require.NoError(t, err)

	record, err := conn.unmarshalCiphertextRecord(rawRecord, true)
	require.NoError(t, err)
	innerPlaintext, sequenceNumber, epoch, err := conn.openCiphertextRecord(record)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), sequenceNumber)
	assert.Equal(t, dtlsflight13.EpochApplication, epoch)
	assert.Equal(t, []byte("application"), innerPlaintext.Content)

	sealed.Header.ConnectionID = nil
	rawRecord, err = sealed.Marshal()
	require.NoError(t, err)
	_, err = conn.unmarshalCiphertextRecord(rawRecord, false)
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidCiphertextHeader)
}

func TestCiphertextConnectionIDDoesNotMigrateWithoutRRC(t *testing.T) {
	conn, peerProtection := newTestConnWithReadProtection(t)
	state, ok := conn.state.(*dtlsstate.State13)
	require.True(t, ok)
	localCID := []byte("local-cid")
	state.CommitNegotiatedExtensions(&negotiation.ConnectionID{
		ClientCID: localCID,
		ServerCID: []byte("remote-cid"),
	})
	conn.setRemoteEpoch(dtlsflight13.EpochApplication)
	conn.decrypted = make(chan any, 1)
	conn.closed = closer.NewCloser()
	activeAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}
	candidateAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 6000}
	conn.rAddr = activeAddr

	sealed, err := peerProtection.SealRecord(recordlayer.CiphertextConfig{ConnectionID: localCID, EpochLow: uint8(dtlsflight13.EpochApplication & recordwire.EpochMask)}, 0, protocol.ContentTypeApplicationData, []byte("application"))
	require.NoError(t, err)
	rawRecord, err := sealed.Marshal()
	require.NoError(t, err)

	_, err = conn.handleIncomingPacket(t.Context(), rawRecord, candidateAddr, nil, true)
	require.NoError(t, err)
	assert.Equal(t, activeAddr.String(), conn.RemoteAddr().String())
}

func TestLatestCIDControlRecordStartsRRC(t *testing.T) {
	keyUpdate, err := (&handshake.Handshake{Header: handshake.Header{MessageSequence: 0}, Message: &handshake.MessageKeyUpdate{RequestUpdate: handshake.KeyUpdateNotRequested}}).Marshal()
	require.NoError(t, err)
	ack, err := (&protocol.ACK{Records: []protocol.RecordNumber{{Epoch: dtlsflight13.EpochApplication, SequenceNumber: 0}}}).Marshal()
	require.NoError(t, err)

	tests := map[string]struct {
		contentType protocol.ContentType
		plaintext   []byte
	}{
		"ACK":       {contentType: protocol.ContentTypeACK, plaintext: ack},
		"KeyUpdate": {contentType: protocol.ContentTypeHandshake, plaintext: keyUpdate},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			testLatestCIDControlRecordStartsRRC(t, test.contentType, test.plaintext)
		})
	}
}

func testLatestCIDControlRecordStartsRRC(
	t *testing.T,
	contentType protocol.ContentType,
	plaintext []byte,
) {
	t.Helper()
	conn, peerProtection := newTestConnWithReadProtection(t)
	conn.cidPathMigrationPolicy = CIDPathMigrationRRC
	state, ok := conn.state.(*dtlsstate.State13)
	require.True(t, ok)
	localCID := []byte("local-cid")
	state.CommitNegotiatedExtensions(&negotiation.ConnectionID{ClientCID: localCID, ServerCID: []byte("remote-cid"), ReturnRoutabilityCheck: true})
	conn.setLocalEpoch(dtlsflight13.EpochApplication)
	conn.setRemoteEpoch(dtlsflight13.EpochApplication)
	activeAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}
	candidateAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 6000}
	conn.rAddr = activeAddr

	local, peer := packetPipe()
	defer func() {
		require.NoError(t, local.Close())
		require.NoError(t, peer.Close())
	}()
	conn.nextConn = netctx.NewPacketConn(local)
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))

	sealed, err := peerProtection.SealRecord(recordlayer.CiphertextConfig{ConnectionID: localCID, EpochLow: uint8(dtlsflight13.EpochApplication & recordwire.EpochMask)}, 0, contentType, plaintext)
	require.NoError(t, err)
	rawRecord, err := sealed.Marshal()
	require.NoError(t, err)

	type readResult struct {
		n   int
		err error
	}
	read := make(chan readResult, 1)
	go func() {
		buf := make([]byte, defaultMTU)
		n, readErr := peer.Read(buf)
		read <- readResult{n: n, err: readErr}
	}()

	_, err = conn.handleIncomingPacket(t.Context(), rawRecord, candidateAddr, nil, true)
	require.NoError(t, err)
	result := <-read
	require.NoError(t, result.err)
	assert.Positive(t, result.n)
	assert.Equal(t, activeAddr.String(), conn.RemoteAddr().String())
}

func TestRRCRequiresProtectionPolicyAndNegotiation(t *testing.T) {
	for name, test := range map[string]struct {
		policy     cidPathMigrationPolicy
		negotiated bool
		epoch      uint16
	}{
		"Unprotected":    {policy: CIDPathMigrationRRC, negotiated: true},
		"PolicyDisabled": {policy: CIDPathMigrationReject, negotiated: true, epoch: 1},
		"NotNegotiated":  {policy: CIDPathMigrationRRC, epoch: 1},
	} {
		t.Run(name, func(t *testing.T) {
			state := dtlsstate.NewState12(true)
			state.CommitNegotiatedExtensions(&negotiation.ConnectionID{ClientCID: []byte("local-cid"), ServerCID: []byte("remote-cid"), ReturnRoutabilityCheck: test.negotiated})
			marked := false
			conn := &Conn{state: &state, cidPathMigrationPolicy: test.policy}
			_, outcome, err := conn.handleRecordContent(
				t.Context(),
				&protocol.ReturnRoutabilityCheck{MessageType: protocol.ReturnRoutabilityCheckPathChallenge},
				incomingPacketState{
					number: protocol.RecordNumber{Epoch: uint64(test.epoch)},
					markPacketAsValid: func() bool {
						marked = true

						return true
					},
				},
				&net.UDPAddr{},
				nil,
			)

			assert.ErrorIs(t, err, dtlserrors.ErrUnexpectedPostHandshakeMessage)
			assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage}, outcome.responseAlert)
			assert.False(t, marked)
		})
	}
}

func TestWriteRRCRequiresPolicyAndNegotiation(t *testing.T) {
	for name, test := range map[string]struct {
		policy     cidPathMigrationPolicy
		negotiated bool
	}{
		"PolicyDisabled": {policy: CIDPathMigrationReject, negotiated: true},
		"NotNegotiated":  {policy: CIDPathMigrationRRC},
	} {
		t.Run(name, func(t *testing.T) {
			state := dtlsstate.NewState12(true)
			state.CommitNegotiatedExtensions(&negotiation.ConnectionID{ClientCID: []byte("local-cid"), ServerCID: []byte("remote-cid"), ReturnRoutabilityCheck: test.negotiated})
			conn := &Conn{state: &state, cidPathMigrationPolicy: test.policy}
			err := (returnRoutabilityConn{conn: conn}).WriteRRC(t.Context(), &net.UDPAddr{}, protocol.ReturnRoutabilityCheckPathChallenge, [protocol.ReturnRoutabilityCheckCookieLength]byte{})
			assert.ErrorIs(t, err, dtlserrors.ErrUnexpectedPostHandshakeMessage)
		})
	}
}

func TestCIDPathMigrationPolicies(t *testing.T) {
	activeAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}
	candidateAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 6000}
	for name, test := range map[string]struct {
		policy       cidPathMigrationPolicy
		expectedAddr net.Addr
		expectedLog  string
	}{
		"Reject": {
			policy: CIDPathMigrationReject, expectedAddr: activeAddr,
			expectedLog: "rejected CID path migration",
		},
		"Unsafe": {policy: CIDPathMigrationUnsafe, expectedAddr: candidateAddr},
		"RRCNotNegotiated": {
			policy: CIDPathMigrationRRC, expectedAddr: activeAddr,
			expectedLog: "RRC was not negotiated",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			conn := &Conn{rAddr: activeAddr, cidPathMigrationPolicy: test.policy, log: logging.NewDefaultLeveledLoggerForScope("dtls", logging.LogLevelError, &logs)}
			(returnRoutabilityConn{conn: conn}).HandleCandidate(
				t.Context(), false, true, true, candidateAddr,
			)

			assert.Equal(t, test.expectedAddr.String(), conn.RemoteAddr().String())
			if test.expectedLog == "" {
				assert.Empty(t, logs.String())
			} else {
				assert.Contains(t, logs.String(), test.expectedLog)
			}
		})
	}
}

func TestOpenCiphertextRecordUsesReadTrafficGeneration(t *testing.T) {
	conn, state, suite := newTrafficKeyTestConn(t)
	handshakeSecret := trafficKeyTestSecret(suite, 0x31)
	applicationSecret := trafficKeyTestSecret(suite, 0x32)
	handshakeProtection := trafficKeyTestProtection(t, suite, handshakeSecret)
	applicationProtection := trafficKeyTestProtection(t, suite, applicationSecret)

	state.TrafficKeys.Install(nil, &dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochHandshake, Secret: handshakeSecret, Protection: handshakeProtection})
	state.TrafficKeys.Install(nil, &dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochApplication, Secret: applicationSecret, Protection: applicationProtection})

	state.SetRemoteEpoch(dtlsflight13.EpochHandshake)
	handshakeRecord := sealTrafficKeyTestRecord(t, handshakeProtection, dtlsflight13.EpochHandshake, protocol.ContentTypeHandshake, []byte("handshake"))
	innerPlaintext, sequenceNumber, epoch, err := conn.openCiphertextRecord(handshakeRecord.parsed(t))
	require.NoError(t, err)
	assert.Equal(t, uint64(0), sequenceNumber)
	assert.Equal(t, dtlsflight13.EpochHandshake, epoch)
	assert.Equal(t, []byte("handshake"), innerPlaintext.Content)

	state.SetRemoteEpoch(dtlsflight13.EpochApplication)
	applicationRecord := sealTrafficKeyTestRecord(t, applicationProtection, dtlsflight13.EpochApplication, protocol.ContentTypeApplicationData, []byte("application"))
	innerPlaintext, sequenceNumber, epoch, err = conn.openCiphertextRecord(applicationRecord.parsed(t))
	require.NoError(t, err)
	assert.Equal(t, uint64(0), sequenceNumber)
	assert.Equal(t, dtlsflight13.EpochApplication, epoch)
	assert.Equal(t, []byte("application"), innerPlaintext.Content)

	wrongDirection := trafficKeyTestProtection(t, suite, trafficKeyTestSecret(suite, 0x33))
	state.TrafficKeys.Install(nil, &dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochApplication, Secret: trafficKeyTestSecret(suite, 0x33), Protection: wrongDirection})
	innerPlaintext, sequenceNumber, epoch, err = conn.openCiphertextRecord(applicationRecord.parsed(t))
	assert.ErrorIs(t, err, errRecordAuthentication)
	assert.Zero(t, innerPlaintext)
	assert.Zero(t, sequenceNumber)
	assert.Zero(t, epoch)

	state.SetRemoteEpoch(4)
	applicationRecord.Header.EpochLow = 0
	innerPlaintext, sequenceNumber, epoch, err = conn.openCiphertextRecord(applicationRecord.parsed(t))
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidEpoch)
	assert.Zero(t, innerPlaintext)
	assert.Zero(t, sequenceNumber)
	assert.Zero(t, epoch)
}

func TestOpenCiphertextRecordRetainsPreviousReadGeneration(t *testing.T) {
	conn, state, suite := newTrafficKeyTestConn(t)
	previousSecret := trafficKeyTestSecret(suite, 0x41)
	currentSecret := trafficKeyTestSecret(suite, 0x42)
	previousProtection := trafficKeyTestProtection(t, suite, previousSecret)
	currentProtection := trafficKeyTestProtection(t, suite, currentSecret)
	state.TrafficKeys.Install(nil, &dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochApplication, Generation: 0, Secret: previousSecret, Protection: previousProtection})
	state.TrafficKeys.Install(nil, &dtlsstate.TrafficGeneration{Epoch: dtlsflight13.EpochApplication + 1, Generation: 1, Secret: currentSecret, Protection: currentProtection})
	state.SetRemoteEpoch(dtlsflight13.EpochApplication + 1)
	record := sealTrafficKeyTestRecord(t, previousProtection, dtlsflight13.EpochApplication, protocol.ContentTypeHandshake, []byte("retransmitted KeyUpdate"))

	innerPlaintext, _, epoch, err := conn.openCiphertextRecord(record.parsed(t))
	require.NoError(t, err)
	assert.Equal(t, dtlsflight13.EpochApplication, epoch)
	assert.Equal(t, []byte("retransmitted KeyUpdate"), innerPlaintext.Content)
}

func TestDTLS13SequenceTrackingAfterAuthentication(t *testing.T) {
	for _, test := range []struct {
		name         string
		tamper       bool
		nextSequence uint64
	}{
		{"authenticated invalid content", false, 65636},
		{"authentication failure", true, 101},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, peer := newTestConnWithReadProtection(t)
			receive := func(sequence uint64, contentType protocol.ContentType, tamper bool) bool {
				record, err := peer.SealRecord(recordlayer.CiphertextConfig{EpochLow: 2}, sequence, contentType, []byte("content"))
				require.NoError(t, err)
				if tamper {
					record.EncryptedRecord[len(record.EncryptedRecord)-1] ^= 1
				}
				raw, err := record.Marshal()
				require.NoError(t, err)
				prepared, ok, err := conn.prepareIncomingPacket(raw, nil, nil, false)
				require.NoError(t, err)
				if ok {
					assert.Equal(t, []byte("content"), prepared.content)
					prepared.markPacketAsValid()
				}

				return ok
			}

			require.True(t, receive(100, protocol.ContentTypeApplicationData, false))
			require.False(t, receive(32868, protocol.ContentTypeChangeCipherSpec, test.tamper))
			require.True(t, receive(test.nextSequence, protocol.ContentTypeApplicationData, false))
		})
	}
}

func TestQueueIfCipherSuiteUninitializedUsesReadTrafficGeneration(t *testing.T) {
	conn, state, suite := newTrafficKeyTestConn(t)
	for _, epoch := range []uint64{dtlsflight13.EpochHandshake, dtlsflight13.EpochApplication} {
		//nolint:gosec //G115
		state.TrafficKeys.Install(nil, &dtlsstate.TrafficGeneration{Epoch: epoch, Secret: trafficKeyTestSecret(suite, byte(epoch)), Protection: trafficKeyTestProtection(t, suite, trafficKeyTestSecret(suite, byte(epoch)))})
		state.SetRemoteEpoch(epoch)
		assert.False(t, conn.queueIfCipherSuiteUninitialized(nil, nil, nil, "traffic key available"))
	}
}

func newTrafficKeyTestConn(t *testing.T) (*Conn, *dtlsstate.State13, cryptosuite.TrafficSuite) {
	t.Helper()

	suite := trafficSuiteForTest(t)
	state := &dtlsstate.State13{Common: &dtlsstate.Common{IsClient: true, LocalVersion: protocol.Version1_3, CipherSuite: suite}, TrafficKeys: &dtlsstate.TrafficKeyState{}}

	return &Conn{state: state}, state, suite
}

func trafficSuiteForTest(t *testing.T) cryptosuite.TrafficSuite {
	t.Helper()

	suite, ok := ciphersuite.ForID(cryptosuite.TLS_AES_128_GCM_SHA256).(cryptosuite.TrafficSuite)
	require.True(t, ok)

	return suite
}

func trafficKeyTestSecret(suite cryptosuite.TrafficSuite, value byte) []byte {
	return bytes.Repeat([]byte{value}, suite.HashFunc()().Size())
}

func trafficKeyTestProtection(
	t *testing.T,
	suite cryptosuite.TrafficSuite,
	secret []byte,
) *testRecordProtection13 {
	t.Helper()

	protection, err := newTestRecordProtection13(suite, secret)
	require.NoError(t, err)

	return protection
}

func sealTrafficKeyTestRecord(t *testing.T, protection *testRecordProtection13, epoch uint64, contentType protocol.ContentType, plaintext []byte) sealedTestRecord {
	t.Helper()

	record, err := protection.SealRecord(recordlayer.CiphertextConfig{EpochLow: uint8(epoch & recordwire.EpochMask), TwoByteSequence: true}, 0, contentType, plaintext)
	require.NoError(t, err)

	return record
}

func assertTrafficKeyTestRecord(
	t *testing.T,
	protection *testRecordProtection13,
	rawRecord []byte,
	want []byte,
) {
	t.Helper()

	record := unmarshalCiphertextRecordForTest(t, rawRecord, 0)
	innerPlaintext, err := protection.OpenRecord(record.Header, 0, record.EncryptedRecord)
	require.NoError(t, err)
	assert.Equal(t, want, innerPlaintext.Content)
}

func TestDetachedConnWritesRRCAsAddressedEvent(t *testing.T) {
	conn, _ := newTestConnWithReadProtection(t)
	conn.cidPathMigrationPolicy = CIDPathMigrationRRC
	state, ok := conn.state.(*dtlsstate.State13)
	require.True(t, ok)
	state.CommitNegotiatedExtensions(&negotiation.ConnectionID{
		ClientCID:              []byte("local-cid"),
		ServerCID:              []byte("remote-cid"),
		ReturnRoutabilityCheck: true,
	})
	conn.setLocalEpoch(dtlsflight13.EpochApplication)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}
	conn.rAddr = addr
	detached := &DetachedConn{}
	conn.detached = detached

	require.NoError(t, (returnRoutabilityConn{conn: conn}).WriteRRC(
		t.Context(), addr, protocol.ReturnRoutabilityCheckPathChallenge,
		[protocol.ReturnRoutabilityCheckCookieLength]byte{},
	))
	event := detached.NextEvent()
	require.Equal(t, DetachedWriteDatagrams, event.Kind)
	require.Equal(t, addr.String(), event.Addr.String())
	require.Len(t, event.Datagrams, 1)
}

func TestDetachedConnEventReadyCoalesces(t *testing.T) {
	conn := &DetachedConn{eventReady: make(chan struct{}, 1)}
	conn.publishEvent(DetachedEvent{Kind: DetachedApplicationData})
	conn.publishEvent(DetachedEvent{Kind: DetachedHandshakeDone})

	requireDetachedEventReady(t, conn)
	select {
	case <-conn.EventReady():
		require.Fail(t, "multiple readiness signals for one nonempty queue")
	default:
	}
	require.Equal(t, DetachedApplicationData, conn.NextEvent().Kind)
	require.Equal(t, DetachedHandshakeDone, conn.NextEvent().Kind)
	require.Equal(t, DetachedNoEvent, conn.NextEvent().Kind)

	conn.publishEvent(DetachedEvent{Kind: DetachedApplicationData})
	require.Equal(t, DetachedApplicationData, conn.NextEvent().Kind)
	require.Equal(t, DetachedNoEvent, conn.NextEvent().Kind)
	select {
	case <-conn.EventReady():
		require.Fail(t, "stale readiness signal after draining events")
	default:
	}

	conn.publishEvent(DetachedEvent{Kind: DetachedHandshakeDone})
	requireDetachedEventReady(t, conn)
}

func TestDetachedConnValidInputCancelsPendingRetransmit(t *testing.T) { //nolint:cyclop
	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	clientAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4444}
	serverAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 5555}

	for name, version := range map[string]protocol.Version{"DTLS12": protocol.Version1_2, "DTLS13": protocol.Version1_3} {
		t.Run(name, func(t *testing.T) {
			client, err := DetachedClient(serverAddr,
				WithInsecureSkipVerify(true),
				WithMinVersion(version),
				WithMaxVersion(version),
				WithFlightInterval(time.Hour),
			)
			require.NoError(t, err)
			server, err := DetachedServer(clientAddr,
				WithCertificates(certificate),
				WithMinVersion(version),
				WithMaxVersion(version),
				WithFlightInterval(time.Hour),
			)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})

			timers := make(chan *detachedTimer, 8)
			client.conn.handshakeConfig.TimerFactory = func(d time.Duration) dtlsconfig.Timer {
				timer := client.newTimer(d).(*detachedTimer) //nolint:forcetypeassert // test factory always returns this type
				timers <- timer

				return timer
			}

			require.NoError(t, server.Start(t.Context()))
			require.NoError(t, client.Start(t.Context()))

			var clientFlight [][]byte
			for event := client.NextEvent(); event.Kind != DetachedNoEvent; event = client.NextEvent() {
				if event.Kind == DetachedWriteDatagrams {
					clientFlight = append(clientFlight, event.Datagrams...)
				}
			}
			require.NotEmpty(t, clientFlight)
			initialTimer := <-timers

			// Keep the valid input operation ahead of the pending timer callback.
			// Stop must claim the timer while fire is waiting for driveMu.
			client.driveMu.Lock()
			locked := true
			defer func() {
				if locked {
					client.driveMu.Unlock()
				}
			}()

			for _, datagram := range clientFlight {
				require.NoError(t, server.HandleDatagram(datagram, clientAddr))
			}
			var serverFlight [][]byte
			for event := server.NextEvent(); event.Kind != DetachedNoEvent; event = server.NextEvent() {
				if event.Kind == DetachedWriteDatagrams {
					serverFlight = append(serverFlight, event.Datagrams...)
				}
			}
			require.NotEmpty(t, serverFlight)

			fireDone := make(chan struct{})
			go func() {
				initialTimer.fire()
				close(fireDone)
			}()
			for _, datagram := range serverFlight {
				select {
				case client.inbound <- addrPkt{rAddr: serverAddr, data: datagram}:
				case <-client.terminal:
					require.NoError(t, client.terminalErr)
				}
				require.NoError(t, client.waitUntilBlocked())
			}
			require.True(t, initialTimer.claimed.Load())

			immediateWrites := 0
			for event := client.NextEvent(); event.Kind != DetachedNoEvent; event = client.NextEvent() {
				if event.Kind == DetachedWriteDatagrams {
					immediateWrites++
				}
			}
			require.Positive(t, immediateWrites)

			client.driveMu.Unlock()
			locked = false
			select {
			case <-fireDone:
			case <-time.After(time.Second):
				require.FailNow(t, "timer callback remained blocked after valid input")
			}
			select {
			case <-client.EventReady():
				require.Fail(t, "canceled retransmit produced an event")
			default:
			}
		})
	}
}

func requireDetachedEventReady(t *testing.T, conn *DetachedConn) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-conn.EventReady():
	case <-timer.C:
		require.FailNow(t, "timed out waiting for a detached event")
	}
}

// sealedTestRecord holds encoder inputs for deterministic wire mutations in tests.
type sealedTestRecord struct {
	Header          recordlayer.CiphertextConfig
	EncryptedRecord []byte
}

func (r sealedTestRecord) Marshal() ([]byte, error) {
	return recordlayer.MarshalCiphertext(r.Header, r.EncryptedRecord)
}

func (r sealedTestRecord) parsed(t *testing.T) recordlayer.ParsedRecord {
	t.Helper()
	raw, err := r.Marshal()
	require.NoError(t, err)
	parsed, err := recordlayer.ParseRecord(raw, len(r.Header.ConnectionID))
	require.NoError(t, err)

	return parsed
}

func TestHandleIncomingPacketControlRecordEpoch(t *testing.T) {
	t.Cleanup(test.CheckRoutines(t))
	defer test.TimeOut(10 * time.Second).Stop()

	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	client, server := handshakePair(t,
		[]ClientOption{WithInsecureSkipVerify(true), WithMaxVersion(protocol.Version1_2)},
		[]ServerOption{WithCertificates(certificate), WithMaxVersion(protocol.Version1_2)},
	)
	for _, result := range []handshakeResult{client, server} {
		require.NoError(t, result.configErr)
		require.NoError(t, result.handshakeError)
	}

	for _, testCase := range []struct {
		name        string
		version     protocol.Version
		remoteEpoch uint64
		recordEpoch uint64
		content     protocol.Content
	}{
		{name: "DTLS12/close_after_handshake", version: protocol.Version1_2, remoteEpoch: 1, content: &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify}},
		{name: "DTLS13/alert_after_keys", version: protocol.Version1_3, remoteEpoch: 2, content: &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}},
		{name: "ACK/before_keys", version: protocol.Version1_3, content: &protocol.ACK{Records: []protocol.RecordNumber{{Epoch: 2}}}},
		{name: "ACK/after_keys", version: protocol.Version1_3, remoteEpoch: 3, content: &protocol.ACK{Records: []protocol.RecordNumber{{Epoch: 2}}}},
		{name: "ACK/mixed_epochs", version: protocol.Version1_3, remoteEpoch: 3, recordEpoch: 2, content: &protocol.ACK{Records: []protocol.RecordNumber{{Epoch: 2}, {Epoch: 3}}}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn, peerProtection := newTestConnWithReadProtection(t)
			common := dtlsstate.CommonState(conn.state)
			common.LocalVersion = testCase.version
			if testCase.version == protocol.Version1_2 {
				conn.state = &dtlsstate.State12{Common: common}
				conn.handshakeEstablished = client.conn.handshakeEstablished
			}
			conn.setRemoteEpoch(testCase.remoteEpoch)
			raw, err := marshalTestRecord(recordlayer.RecordConfig{Version: protocol.Version1_2}, testCase.content)
			require.NoError(t, err)
			if testCase.recordEpoch != 0 {
				plaintext, marshalErr := testCase.content.Marshal()
				require.NoError(t, marshalErr)
				sealed, sealErr := peerProtection.SealRecord(recordlayer.CiphertextConfig{
					EpochLow: uint8(testCase.recordEpoch & recordwire.EpochMask),
				}, 0, testCase.content.ContentType(), plaintext)
				require.NoError(t, sealErr)
				raw, err = sealed.Marshal()
				require.NoError(t, err)
			}

			outcome, err := conn.handleIncomingPacket(t.Context(), raw, nil, nil, false)
			require.NoError(t, err)
			assert.Equal(t, packetOutcome{}, outcome)
			if detector := common.ReplayDetector[testCase.recordEpoch]; detector != nil {
				_, acceptable := detector.Check(0)
				assert.True(t, acceptable, "discarded records must not consume replay sequence numbers")
			}
		})
	}
}

type limitedTrafficSuite struct {
	cryptosuite.TrafficSuite
	limits cryptosuite.UsageLimits
}

func (s *limitedTrafficSuite) ID() cryptosuite.ID                   { return 0xffa8 }
func (s *limitedTrafficSuite) UsageLimits() cryptosuite.UsageLimits { return s.limits }

func trafficSuiteWithLimits(t *testing.T, seals, failures uint64) *limitedTrafficSuite {
	t.Helper()

	return &limitedTrafficSuite{
		TrafficSuite: trafficSuiteForTest(t),
		limits:       cryptosuite.UsageLimits{MaxSealedRecords: seals, MaxAuthenticationFailures: failures},
	}
}

type limitedConnectionSuite struct {
	cryptosuite.ConnectionSuite
}

func (s *limitedConnectionSuite) ID() cryptosuite.ID { return 0xffa9 }

func (s *limitedConnectionSuite) UsageLimits() cryptosuite.UsageLimits {
	return cryptosuite.UsageLimits{MaxSealedRecords: 8, MaxAuthenticationFailures: 2}
}

func limitedTrafficPair(t *testing.T, version protocol.Version) (*Conn, *Conn) {
	t.Helper()
	var suite cryptosuite.Suite = trafficSuiteWithLimits(t, 8, 2)
	if version == protocol.Version1_2 {
		connectionSuite, ok := ciphersuite.ForID(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).(cryptosuite.ConnectionSuite)
		require.True(t, ok)
		suite = &limitedConnectionSuite{ConnectionSuite: connectionSuite}
	}
	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	custom := WithCustomCipherSuites(func() []cryptosuite.Suite { return []cryptosuite.Suite{suite} })
	client, server := handshakePair(t,
		[]ClientOption{WithMinVersion(version), WithMaxVersion(version), WithInsecureSkipVerify(true), WithCipherSuites(suite.ID()), custom},
		[]ServerOption{WithMinVersion(version), WithMaxVersion(version), WithCertificates(certificate), WithCipherSuites(suite.ID()), custom})
	require.NoError(t, client.configErr)
	require.NoError(t, server.configErr)
	require.NoError(t, client.handshakeError)
	require.NoError(t, server.handshakeError)

	return client.conn, server.conn
}

func TestConnectionKeyUsage(t *testing.T) {
	for _, version := range []protocol.Version{protocol.Version1_2, protocol.Version1_3} {
		t.Run(fmt.Sprintf("%x", version), func(t *testing.T) {
			client, server := limitedTrafficPair(t, version)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, client.SetWriteDeadline(time.Now().Add(5*time.Second)))
			require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
			before, ok := client.ConnectionState()
			require.True(t, ok)
			require.NotNil(t, before.KeyUsage)
			buffer := make([]byte, 32)
			for range 12 {
				_, err := client.Write([]byte("payload"))
				require.NoError(t, err)
				_, err = server.Read(buffer)
				require.NoError(t, err)
			}
			after, ok := client.ConnectionState()
			require.True(t, ok)
			require.GreaterOrEqual(t, after.KeyUsage.SealedRecords, before.KeyUsage.SealedRecords+12)
			require.Equal(t, uint64(8), after.KeyUsage.RecommendedLimits.MaxSealedRecords)
			require.Zero(t, after.KeyUsage.RemainingSealedRecords)
			require.Less(t, before.KeyUsage.SealedRecords, after.KeyUsage.SealedRecords, "snapshots must not change")

			packet := &dtlsflight.Outbound{Epoch: after.KeyUsage.WriteEpoch, Content: &protocol.ApplicationData{Data: []byte("payload")}, Protection: dtlsflight.ProtectionCiphertext}
			client.writeLock.Lock()
			datagrams, address, err := client.prepareRawPacketsTracked([]*dtlsflight.Outbound{packet})
			client.writeLock.Unlock()
			require.NoError(t, err)
			require.Len(t, datagrams, 1)
			raw := datagrams[0].raw
			raw[len(raw)-1] ^= 1
			for range 3 {
				_, err = client.nextConn.WriteToContext(ctx, raw, address)
				require.NoError(t, err)
			}
			_, err = client.Write([]byte("still connected"))
			require.NoError(t, err)
			n, err := server.Read(buffer)
			require.NoError(t, err)
			require.Equal(t, "still connected", string(buffer[:n]))
			received, ok := server.ConnectionState()
			require.True(t, ok)
			require.Equal(t, uint64(3), received.KeyUsage.AuthenticationFailures)
			require.Equal(t, uint64(2), received.KeyUsage.RecommendedLimits.MaxAuthenticationFailures)
			require.Zero(t, received.KeyUsage.RemainingAuthenticationFailures)
			require.False(t, client.isConnectionClosed())
			require.False(t, server.isConnectionClosed())

			if version == protocol.Version1_3 {
				require.NoError(t, client.UpdateKeys(ctx, KeyUpdateOptions{}))
				updated, ok := client.ConnectionState()
				require.True(t, ok)
				require.Equal(t, after.KeyUsage.WriteEpoch+1, updated.KeyUsage.WriteEpoch)
				require.Positive(t, updated.KeyUsage.RemainingSealedRecords)
			}
		})
	}
}
