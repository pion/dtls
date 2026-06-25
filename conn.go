// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/fips140"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3/internal/closer"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/pion/transport/v4/deadline"
	"github.com/pion/transport/v4/netctx"
	"github.com/pion/transport/v4/replaydetector"
)

const (
	initialTickerInterval = time.Second
	cookieLength          = 20
	sessionLength         = 32
	inboundBufferSize     = 8192
	// Default replay protection window is specified by RFC 6347 Section 4.1.2.6.
	defaultReplayProtectionWindow = 64
	// maxAppDataPacketQueueSize is the maximum number of app data packets we will.
	// enqueue before the handshake is completed.
	maxAppDataPacketQueueSize = 100
)

func invalidKeyingLabels() map[string]bool {
	return map[string]bool{
		"client finished": true,
		"server finished": true,
		"master secret":   true,
		"key expansion":   true,
	}
}

func toConfigCipherSuites(cipherSuites []CipherSuite) []dtlsconfig.CipherSuite {
	out := make([]dtlsconfig.CipherSuite, 0, len(cipherSuites))
	for _, cipherSuite := range cipherSuites {
		out = append(out, cipherSuite)
	}

	return out
}

type addrPkt struct {
	rAddr net.Addr
	data  []byte
}

type recvHandshakeState struct {
	done         chan struct{}
	isRetransmit bool
}

type handshakeStart struct {
	flight12     dtlsflight.Flight12
	flight13     dtlsflight.Flight13
	fsmState     handshakeState
	flights      []*dtlsflight.Packet
	transcript13 *handshakeTranscript13
	postSetup    func(context.Context)
}

// Conn represents a DTLS connection.
type Conn struct {
	lock           sync.RWMutex      // Internal lock (must not be public)
	nextConn       netctx.PacketConn // Embedded Conn, typically a udpconn we read/write from
	fragmentBuffer *fragmentBuffer   // out-of-order and missing fragment handling
	handshakeCache *dtlsflight.Cache // caching of handshake messages for verifyData generation
	decrypted      chan any          // Decrypted Application Data or error, pull by calling `Read`
	rAddr          net.Addr
	state          dtlsstate.State // Internal state

	maximumTransmissionUnit int
	paddingLengthGenerator  func(uint) uint

	handshakeCompletedSuccessfully atomic.Bool
	handshakeMutex                 sync.Mutex
	handshakeDone                  chan struct{}

	encryptedPackets []addrPkt

	connectionClosedByUser bool
	closeLock              sync.Mutex
	closed                 *closer.Closer

	readDeadline  *deadline.Deadline
	writeDeadline *deadline.Deadline

	log logging.LeveledLogger

	reading               chan struct{}
	handshakeRecv         chan recvHandshakeState
	cancelHandshaker      func()
	cancelHandshakeReader func()

	fsm handshakeFSM

	replayProtectionWindow uint

	handshakeConfig *handshakeConfig
}

// createConn creates a new DTLS connection.
// Caller is responsible for validating the config before calling this function.
//
//nolint:cyclop
func createConn(
	nextConn net.PacketConn,
	rAddr net.Addr,
	config *dtlsConfig,
	isClient bool,
	resumeState *dtlsstate.State,
) (*Conn, error) {
	if nextConn == nil {
		return nil, dtlserrors.ErrNilNextConn
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	logger := loggerFactory.NewLogger("dtls")

	mtu := config.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	replayProtectionWindow := config.ReplayProtectionWindow
	if replayProtectionWindow <= 0 {
		replayProtectionWindow = defaultReplayProtectionWindow
	}

	paddingLengthGenerator := config.PaddingLengthGenerator
	if paddingLengthGenerator == nil {
		paddingLengthGenerator = func(uint) uint { return 0 }
	}

	minVersion, maxVersion := normalizeProtocolVersionRange(config.MinVersion, config.MaxVersion)

	cipherSuites, err := parseCipherSuitesForVersions(
		config.CipherSuites,
		config.customCipherSuites,
		config.includeCertificateSuites(),
		config.psk != nil,
		minVersion,
		maxVersion,
	)
	if err != nil {
		return nil, err
	}

	signatureSchemes, err := signaturehash.ParseSignatureSchemes(config.SignatureSchemes, config.InsecureHashes)
	if err != nil {
		return nil, err
	}

	// Parse certificate signature schemes only if explicitly configured
	var certSignatureSchemes []signaturehash.Algorithm
	if len(config.CertificateSignatureSchemes) > 0 {
		certSignatureSchemes, err = signaturehash.ParseSignatureSchemes(
			config.CertificateSignatureSchemes,
			config.InsecureHashes,
		)
		if err != nil {
			return nil, err
		}
	}

	workerInterval := initialTickerInterval
	if config.FlightInterval > 0 {
		workerInterval = config.FlightInterval
	}

	serverName := config.ServerName
	// Do not allow the use of an IP address literal as an SNI value.
	// See RFC 6066, Section 3.
	if net.ParseIP(serverName) != nil {
		serverName = ""
	}

	curves := config.EllipticCurves
	if len(curves) == 0 {
		curves = defaultCurves
	}

	if fips140.Enabled() {
		// On FIPS systems, filter out non-approved curves
		filtered := make([]elliptic.Curve, 0, len(curves))
		for _, c := range curves {
			if c != elliptic.X25519 {
				filtered = append(filtered, c)
			}
		}
		curves = filtered
	}

	var customCipherSuites func() []dtlsconfig.CipherSuite
	if config.customCipherSuites != nil {
		customCipherSuites = func() []dtlsconfig.CipherSuite {
			return toConfigCipherSuites(config.customCipherSuites())
		}
	}

	var verifyConnection func(*dtlsstate.State) error
	if config.verifyConnection != nil {
		verifyConnection = func(state *dtlsstate.State) error {
			stateSnapshot, err := generateState(state)
			if err != nil {
				return err
			}

			return config.verifyConnection(stateSnapshot)
		}
	}

	var getCertificate func(*dtlsconfig.ClientHelloInfo) (*tls.Certificate, error)
	if config.getCertificate != nil {
		getCertificate = func(info *dtlsconfig.ClientHelloInfo) (*tls.Certificate, error) {
			return config.getCertificate(&ClientHelloInfo{
				ServerName:   info.ServerName,
				CipherSuites: info.CipherSuites,
				RandomBytes:  info.RandomBytes,
			})
		}
	}

	var getClientCertificate func(*dtlsconfig.CertificateRequestInfo) (*tls.Certificate, error)
	if config.getClientCertificate != nil {
		getClientCertificate = func(info *dtlsconfig.CertificateRequestInfo) (*tls.Certificate, error) {
			return config.getClientCertificate(&CertificateRequestInfo{AcceptableCAs: info.AcceptableCAs})
		}
	}

	getSession := func(key []byte) ([]byte, []byte, error) {
		session, err := config.sessionStore.Get(key)

		return session.ID, session.Secret, err
	}
	setSession := func(key, id, secret []byte) error {
		return config.sessionStore.Set(key, Session{ID: id, Secret: secret})
	}
	delSession := func(key []byte) error {
		return config.sessionStore.Del(key)
	}

	handshakeConfig := &handshakeConfig{
		LocalPSKCallback:              config.psk,
		LocalPSKIdentityHint:          config.PSKIdentityHint,
		LocalCipherSuites:             cipherSuites,
		LocalSignatureSchemes:         signatureSchemes,
		LocalCertSignatureSchemes:     certSignatureSchemes,
		ExtendedMasterSecret:          dtlsconfig.ExtendedMasterSecretType(config.ExtendedMasterSecret),
		LocalSRTPProtectionProfiles:   config.SRTPProtectionProfiles,
		LocalSRTPMasterKeyIdentifier:  config.SRTPMasterKeyIdentifier,
		ServerName:                    serverName,
		SupportedProtocols:            config.SupportedProtocols,
		ClientAuth:                    dtlsconfig.ClientAuthType(config.ClientAuth),
		LocalCertificates:             config.Certificates,
		InsecureSkipVerify:            config.InsecureSkipVerify,
		VerifyPeerCertificate:         config.VerifyPeerCertificate,
		VerifyConnection:              verifyConnection,
		HasSessionStore:               config.sessionStore != nil,
		GetSession:                    getSession,
		SetSession:                    setSession,
		DelSession:                    delSession,
		RootCAs:                       config.RootCAs,
		ClientCAs:                     config.ClientCAs,
		CustomCipherSuites:            customCipherSuites,
		InitialRetransmitInterval:     workerInterval,
		DisableRetransmitBackoff:      config.DisableRetransmitBackoff,
		Log:                           logger,
		InitialEpoch:                  0,
		KeyLogWriter:                  config.KeyLogWriter,
		EllipticCurves:                curves,
		LocalGetCertificate:           getCertificate,
		LocalGetClientCertificate:     getClientCertificate,
		InsecureSkipHelloVerify:       config.InsecureSkipVerifyHello,
		ConnectionIDGenerator:         config.ConnectionIDGenerator,
		HelloRandomBytesGenerator:     config.HelloRandomBytesGenerator,
		ClientHelloMessageHook:        config.ClientHelloMessageHook,
		ServerHelloMessageHook:        config.ServerHelloMessageHook,
		CertificateRequestMessageHook: config.CertificateRequestMessageHook,
		ResumeState:                   resumeState,
		MinVersion:                    minVersion,
		MaxVersion:                    maxVersion,
	}

	conn := &Conn{
		rAddr:                   rAddr,
		nextConn:                netctx.NewPacketConn(nextConn),
		handshakeConfig:         handshakeConfig,
		fragmentBuffer:          newFragmentBuffer(),
		handshakeCache:          dtlsflight.NewCache(),
		maximumTransmissionUnit: mtu,
		paddingLengthGenerator:  paddingLengthGenerator,

		decrypted: make(chan any, 1),
		log:       logger,

		readDeadline:  deadline.New(),
		writeDeadline: deadline.New(),

		reading:               make(chan struct{}, 1),
		handshakeRecv:         make(chan recvHandshakeState),
		closed:                closer.NewCloser(),
		cancelHandshaker:      func() {},
		cancelHandshakeReader: func() {},

		replayProtectionWindow: uint(replayProtectionWindow), //nolint:gosec // G115

		state: dtlsstate.State{
			IsClient: isClient,
		},
	}

	conn.setRemoteEpoch(0)
	conn.setLocalEpoch(0)

	return conn, nil
}

// Handshake runs the client or server DTLS handshake
// protocol if it has not yet been run.
//
// Most uses of this package need not call Handshake explicitly: the
// first [Conn.Read] or [Conn.Write] will call it automatically.
//
// For control over canceling or setting a timeout on a handshake, use
// [Conn.HandshakeContext].
func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext runs the client or server DTLS handshake
// protocol if it has not yet been run.
//
// The provided Context must be non-nil. If the context is canceled before
// the handshake is complete, the handshake is interrupted and an error is returned.
// Once the handshake has completed, cancellation of the context will not affect the
// connection.
//
// Most uses of this package need not call HandshakeContext explicitly: the
// first [Conn.Read] or [Conn.Write] will call it automatically.
func (c *Conn) HandshakeContext(ctx context.Context) error { //nolint:cyclop
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.isHandshakeCompletedSuccessfully() {
		return nil
	}

	handshakeDone := make(chan struct{})
	defer close(handshakeDone)
	c.closeLock.Lock()
	c.handshakeDone = handshakeDone
	c.closeLock.Unlock()

	// rfc5246#section-7.4.3
	// In addition, the hash and signature algorithms MUST be compatible
	// with the key in the server's end-entity certificate.
	if !c.state.IsClient {
		cert, err := c.handshakeConfig.GetCertificate(&dtlsconfig.ClientHelloInfo{})
		if err != nil && !errors.Is(err, dtlserrors.ErrNoCertificates) {
			return err
		}
		c.handshakeConfig.LocalCipherSuites = filterCipherSuitesForCertificate(
			cert,
			c.handshakeConfig.LocalCipherSuites,
		)
	}

	start, err := c.prepareHandshakeStart(ctx)
	if err != nil {
		return err
	}

	c.handshakeConfig.LocalCipherSuites = filterCipherSuitesForVersion(
		c.handshakeConfig.LocalCipherSuites,
		c.state.LocalVersion,
	)
	if len(c.handshakeConfig.LocalCipherSuites) == 0 {
		return dtlserrors.ErrNoAvailableCipherSuites
	}

	if err := c.handshake(ctx, start); err != nil {
		return err
	}

	if c.state.LocalVersion == protocol.Version1_3 {
		c.log.Trace("Handshake DTLS 1.3 Completed")
	} else {
		c.log.Trace("Handshake Completed")
	}

	return nil
}

// prepareHandshakeStart negotiates the DTLS version and decides how the FSM should start.
//
// There are three modes for the version:
// - DTLS 1.2 only
// - DTLS 1.3 only
// - Dual-stack (this mode sends or read handshake messages without starting a FSM)
//
// In dual-stack client mode, flights holds the already-sent ClientHello and
// transcript13 carries the same ClientHello into the DTLS 1.3 FSM.
// nolint:cyclop
func (c *Conn) prepareHandshakeStart(ctx context.Context) (handshakeStart, error) {
	switch {
	// DTLS 1.2 only
	case c.state.IsClient && c.handshakeConfig.MaxVersion == protocol.Version1_2:
		c.state.LocalVersion = protocol.Version1_2
		if c.handshakeConfig.ResumeState != nil {
			c.state = *c.handshakeConfig.ResumeState
			c.state.LocalVersion = protocol.Version1_2

			return handshakeStart{flight12: dtlsflight.Flight5, fsmState: handshakeFinished}, nil
		}

		return handshakeStart{flight12: dtlsflight.Flight1, fsmState: handshakePreparing}, nil
	case !c.state.IsClient && c.handshakeConfig.MaxVersion == protocol.Version1_2:
		c.state.LocalVersion = protocol.Version1_2
		if c.handshakeConfig.ResumeState != nil {
			c.state = *c.handshakeConfig.ResumeState
			c.state.LocalVersion = protocol.Version1_2

			return handshakeStart{flight12: dtlsflight.Flight6, fsmState: handshakeFinished}, nil
		}

		return handshakeStart{flight12: dtlsflight.Flight0, fsmState: handshakePreparing}, nil

	// DTLS 1.3 only
	case c.state.IsClient && c.handshakeConfig.MinVersion == protocol.Version1_3:
		c.state.LocalVersion = protocol.Version1_3

		return handshakeStart{flight13: dtlsflight.Flight13_1, fsmState: handshakePreparing}, nil
	case !c.state.IsClient && c.handshakeConfig.MinVersion == protocol.Version1_3:
		c.state.LocalVersion = protocol.Version1_3

		return handshakeStart{flight13: dtlsflight.Flight13_0, fsmState: handshakePreparing}, nil

	// Dual-stack
	// This mode sends or read handshake messages to decide version without starting a FSM
	case c.state.IsClient:
		initialFlights, initialTranscript13, err := c.negotiateVersionClient(ctx)
		if err != nil {
			return handshakeStart{}, err
		}

		primer := func(ctx context.Context) {
			go c.primeHandshakeRecv(ctx)
		}

		return handshakeStart{
			flight12:     dtlsflight.Flight1,
			flight13:     dtlsflight.Flight13_1,
			fsmState:     handshakeWaiting,
			flights:      initialFlights,
			transcript13: initialTranscript13,
			postSetup:    primer,
		}, nil
	default:
		err := c.negotiateVersionServer(ctx)
		if err != nil {
			return handshakeStart{}, err
		}

		return handshakeStart{
			flight12: dtlsflight.Flight0,
			flight13: dtlsflight.Flight13_0,
			fsmState: handshakePreparing,
		}, nil
	}
}

func dialWithConfig(network string, rAddr *net.UDPAddr, config *dtlsConfig) (*Conn, error) {
	// net.ListenUDP is used rather than net.DialUDP as the latter prevents the
	// use of net.PacketConn.WriteTo.
	// https://github.com/golang/go/blob/ce5e37ec21442c6eb13a43e68ca20129102ebac0/src/net/udpsock_posix.go#L115
	pConn, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}

	return clientWithConfig(pConn, rAddr, config)
}

// DialWithOptions connects to the given network address and establishes a DTLS connection on top.
func DialWithOptions(network string, rAddr *net.UDPAddr, opts ...ClientOption) (*Conn, error) {
	config, err := buildClientConfig(opts...)
	if err != nil {
		return nil, err
	}

	return dialWithConfig(network, rAddr, config)
}

func clientWithConfig(conn net.PacketConn, rAddr net.Addr, config *dtlsConfig) (*Conn, error) {
	switch {
	case config == nil:
		return nil, dtlserrors.ErrNoConfigProvided
	case config.psk != nil && config.PSKIdentityHint == nil:
		return nil, dtlserrors.ErrPSKAndIdentityMustBeSetForClient
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return createConn(conn, rAddr, config, true, nil)
}

// ClientWithOptions establishes a DTLS connection over an existing connection.
func ClientWithOptions(conn net.PacketConn, rAddr net.Addr, opts ...ClientOption) (*Conn, error) {
	config, err := buildClientConfig(opts...)
	if err != nil {
		return nil, err
	}

	return clientWithConfig(conn, rAddr, config)
}

func serverWithConfig(conn net.PacketConn, rAddr net.Addr, config *dtlsConfig) (*Conn, error) {
	if config == nil {
		return nil, dtlserrors.ErrNoConfigProvided
	}
	if config.OnConnectionAttempt != nil {
		if err := config.OnConnectionAttempt(rAddr); err != nil {
			return nil, err
		}
	}

	return createConn(conn, rAddr, config, false, nil)
}

func serverWithValidatedConfig(conn net.PacketConn, rAddr net.Addr, config *dtlsConfig) (*Conn, error) {
	if config == nil {
		return nil, dtlserrors.ErrNoConfigProvided
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return serverWithConfig(conn, rAddr, config)
}

// ServerWithOptions listens for incoming DTLS connections.
func ServerWithOptions(conn net.PacketConn, rAddr net.Addr, opts ...ServerOption) (*Conn, error) {
	config, err := buildServerConfig(opts...)
	if err != nil {
		return nil, err
	}

	return serverWithValidatedConfig(conn, rAddr, config)
}

// Read reads data from the connection.
func (c *Conn) Read(buff []byte) (n int, err error) { //nolint:cyclop
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	select {
	case <-c.readDeadline.Done():
		return 0, dtlserrors.ErrDeadlineExceeded
	default:
	}

	for {
		select {
		case <-c.readDeadline.Done():
			return 0, dtlserrors.ErrDeadlineExceeded
		case out, ok := <-c.decrypted:
			if !ok {
				return 0, io.EOF
			}
			switch val := out.(type) {
			case ([]byte):
				if len(buff) < len(val) {
					return 0, dtlserrors.ErrBufferTooSmall
				}
				copy(buff, val)

				return len(val), nil
			case (error):
				return 0, val
			}
		}
	}
}

// Write writes len(payload) bytes from payload to the DTLS connection.
func (c *Conn) Write(payload []byte) (int, error) {
	if c.isConnectionClosed() {
		return 0, ErrConnClosed
	}

	select {
	case <-c.writeDeadline.Done():
		return 0, dtlserrors.ErrDeadlineExceeded
	default:
	}

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	//nolint:godox
	// TODO: check for version
	return len(payload), c.writePackets(c.writeDeadline, []*dtlsflight.Packet{
		{
			Record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Epoch:   c.state.GetLocalEpoch(),
					Version: protocol.Version1_2,
				},
				Content: &protocol.ApplicationData{
					Data: payload,
				},
			},
			ShouldWrapCID: len(c.state.RemoteConnectionID) > 0,
			ShouldEncrypt: true,
		},
	})
}

// Close closes the connection.
func (c *Conn) Close() error {
	err := c.close(true) //nolint:contextcheck
	c.closeLock.Lock()
	handshakeDone := c.handshakeDone
	c.closeLock.Unlock()
	if handshakeDone != nil {
		<-handshakeDone
	}

	return err
}

// ConnectionState returns basic DTLS details about the connection.
// Note that this replaced the `Export` function of v1.
func (c *Conn) ConnectionState() (State, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	state, err := generateState(&c.state)
	if err != nil {
		return State{}, false
	}

	return *state, true
}

// SelectedSRTPProtectionProfile returns the selected SRTPProtectionProfile.
func (c *Conn) SelectedSRTPProtectionProfile() (SRTPProtectionProfile, bool) {
	profile := c.state.GetSRTPProtectionProfile()
	if profile == 0 {
		return 0, false
	}

	return profile, true
}

// RemoteSRTPMasterKeyIdentifier returns the MasterKeyIdentifier value from the use_srtp.
func (c *Conn) RemoteSRTPMasterKeyIdentifier() ([]byte, bool) {
	if profile := c.state.GetSRTPProtectionProfile(); profile == 0 {
		return nil, false
	}

	return c.state.RemoteSRTPMasterKeyIdentifier, true
}

func (c *Conn) writePackets(ctx context.Context, pkts []*dtlsflight.Packet) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	var rawPackets [][]byte

	for _, pkt := range pkts {
		if dtlsHandshake, ok := pkt.Record.Content.(*handshake.Handshake); ok {
			handshakeRaw, err := pkt.Record.Marshal()
			if err != nil {
				return err
			}

			c.log.Tracef("[handshake:%v] -> %s (epoch: %d, seq: %d)",
				srvCliStr(c.state.IsClient), dtlsHandshake.Header.Type.String(),
				pkt.Record.Header.Epoch, dtlsHandshake.Header.MessageSequence)

			c.handshakeCache.Push(
				handshakeRaw[recordlayer.FixedHeaderSize:],
				pkt.Record.Header.Epoch,
				dtlsHandshake.Header.MessageSequence,
				dtlsHandshake.Header.Type,
				c.state.IsClient,
			)

			rawHandshakePackets, err := c.processHandshakePacket(pkt, dtlsHandshake)
			if err != nil {
				return err
			}
			rawPackets = append(rawPackets, rawHandshakePackets...)
		} else {
			rawPacket, err := c.processPacket(pkt)
			if err != nil {
				return err
			}
			rawPackets = append(rawPackets, rawPacket)
		}
	}
	if len(rawPackets) == 0 {
		return nil
	}
	compactedRawPackets := c.compactRawPackets(rawPackets)

	for _, compactedRawPackets := range compactedRawPackets {
		if _, err := c.nextConn.WriteToContext(ctx, compactedRawPackets, c.rAddr); err != nil {
			return netError(err)
		}
	}

	return nil
}

func (c *Conn) compactRawPackets(rawPackets [][]byte) [][]byte {
	// avoid a useless copy in the common case
	if len(rawPackets) == 1 {
		return rawPackets
	}

	combinedRawPackets := make([][]byte, 0)
	currentCombinedRawPacket := make([]byte, 0)

	for _, rawPacket := range rawPackets {
		if len(currentCombinedRawPacket) > 0 && len(currentCombinedRawPacket)+len(rawPacket) >= c.maximumTransmissionUnit {
			combinedRawPackets = append(combinedRawPackets, currentCombinedRawPacket)
			currentCombinedRawPacket = []byte{}
		}
		currentCombinedRawPacket = append(currentCombinedRawPacket, rawPacket...)
	}

	combinedRawPackets = append(combinedRawPackets, currentCombinedRawPacket)

	return combinedRawPackets
}

func (c *Conn) processPacket(pkt *dtlsflight.Packet) ([]byte, error) { //nolint:cyclop
	epoch := pkt.Record.Header.Epoch
	for len(c.state.LocalSequenceNumber) <= int(epoch) {
		c.state.LocalSequenceNumber = append(c.state.LocalSequenceNumber, uint64(0))
	}
	seq := atomic.AddUint64(&c.state.LocalSequenceNumber[epoch], 1) - 1
	if seq > recordlayer.MaxSequenceNumber {
		// RFC 6347 Section 4.1.0
		// The implementation must either abandon an association or rehandshake
		// prior to allowing the sequence number to wrap.
		return nil, dtlserrors.ErrSequenceNumberOverflow
	}
	pkt.Record.Header.SequenceNumber = seq

	var rawPacket []byte
	if pkt.ShouldWrapCID { //nolint:nestif
		// Record must be marshaled to populate fields used in inner plaintext.
		if _, err := pkt.Record.Marshal(); err != nil {
			return nil, err
		}
		content, err := pkt.Record.Content.Marshal()
		if err != nil {
			return nil, err
		}
		inner := &recordlayer.InnerPlaintext{
			Content:  content,
			RealType: pkt.Record.Header.ContentType,
		}
		rawInner, err := inner.Marshal() //nolint:govet
		if err != nil {
			return nil, err
		}
		cidHeader := &recordlayer.Header{
			Version:        pkt.Record.Header.Version,
			ContentType:    protocol.ContentTypeConnectionID,
			Epoch:          pkt.Record.Header.Epoch,
			ContentLen:     uint16(len(rawInner)), //nolint:gosec //G115
			ConnectionID:   c.state.RemoteConnectionID,
			SequenceNumber: pkt.Record.Header.SequenceNumber,
		}
		rawPacket, err = cidHeader.Marshal()
		if err != nil {
			return nil, err
		}
		pkt.Record.Header = *cidHeader
		rawPacket = append(rawPacket, rawInner...)
	} else {
		var err error
		rawPacket, err = pkt.Record.Marshal()
		if err != nil {
			return nil, err
		}
	}

	if pkt.ShouldEncrypt {
		var err error
		rawPacket, err = c.state.CipherSuite.Encrypt(pkt.Record, rawPacket)
		if err != nil {
			return nil, err
		}
	}

	return rawPacket, nil
}

//nolint:cyclop
func (c *Conn) processHandshakePacket(pkt *dtlsflight.Packet, dtlsHandshake *handshake.Handshake) ([][]byte, error) {
	rawPackets := make([][]byte, 0)

	handshakeFragments, err := c.fragmentHandshake(dtlsHandshake)
	if err != nil {
		return nil, err
	}
	epoch := pkt.Record.Header.Epoch
	for len(c.state.LocalSequenceNumber) <= int(epoch) {
		c.state.LocalSequenceNumber = append(c.state.LocalSequenceNumber, uint64(0))
	}

	for _, handshakeFragment := range handshakeFragments {
		seq := atomic.AddUint64(&c.state.LocalSequenceNumber[epoch], 1) - 1
		if seq > recordlayer.MaxSequenceNumber {
			return nil, dtlserrors.ErrSequenceNumberOverflow
		}

		var rawPacket []byte
		if pkt.ShouldWrapCID {
			inner := &recordlayer.InnerPlaintext{
				Content:  handshakeFragment,
				RealType: protocol.ContentTypeHandshake,
				Zeros:    c.paddingLengthGenerator(uint(len(handshakeFragment))),
			}
			rawInner, err := inner.Marshal() //nolint:govet
			if err != nil {
				return nil, err
			}
			cidHeader := &recordlayer.Header{
				Version:        pkt.Record.Header.Version,
				ContentType:    protocol.ContentTypeConnectionID,
				Epoch:          pkt.Record.Header.Epoch,
				ContentLen:     uint16(len(rawInner)), //nolint:gosec //G115
				ConnectionID:   c.state.RemoteConnectionID,
				SequenceNumber: pkt.Record.Header.SequenceNumber,
			}
			rawPacket, err = cidHeader.Marshal()
			if err != nil {
				return nil, err
			}
			pkt.Record.Header = *cidHeader
			rawPacket = append(rawPacket, rawInner...)
		} else {
			recordlayerHeader := &recordlayer.Header{
				Version:        pkt.Record.Header.Version,
				ContentType:    pkt.Record.Header.ContentType,
				ContentLen:     uint16(len(handshakeFragment)), //nolint:gosec // G115
				Epoch:          pkt.Record.Header.Epoch,
				SequenceNumber: seq,
			}

			rawPacket, err = recordlayerHeader.Marshal()
			if err != nil {
				return nil, err
			}

			pkt.Record.Header = *recordlayerHeader
			rawPacket = append(rawPacket, handshakeFragment...)
		}

		if pkt.ShouldEncrypt {
			var err error
			rawPacket, err = c.state.CipherSuite.Encrypt(pkt.Record, rawPacket)
			if err != nil {
				return nil, err
			}
		}

		rawPackets = append(rawPackets, rawPacket)
	}

	return rawPackets, nil
}

func (c *Conn) fragmentHandshake(dtlsHandshake *handshake.Handshake) ([][]byte, error) {
	content, err := dtlsHandshake.Message.Marshal()
	if err != nil {
		return nil, err
	}

	fragmentedHandshakes := make([][]byte, 0)

	contentFragments := splitBytes(content, c.maximumTransmissionUnit)
	if len(contentFragments) == 0 {
		contentFragments = [][]byte{
			{},
		}
	}

	offset := 0
	for _, contentFragment := range contentFragments {
		contentFragmentLen := len(contentFragment)

		headerFragment := &handshake.Header{
			Type:            dtlsHandshake.Header.Type,
			Length:          dtlsHandshake.Header.Length,
			MessageSequence: dtlsHandshake.Header.MessageSequence,
			FragmentOffset:  uint32(offset),             //nolint:gosec // G115
			FragmentLength:  uint32(contentFragmentLen), //nolint:gosec // G115
		}

		offset += contentFragmentLen

		fragmentedHandshake, err := headerFragment.Marshal()
		if err != nil {
			return nil, err
		}

		fragmentedHandshake = append(fragmentedHandshake, contentFragment...)
		fragmentedHandshakes = append(fragmentedHandshakes, fragmentedHandshake)
	}

	return fragmentedHandshakes, nil
}

var poolReadBuffer = sync.Pool{ //nolint:gochecknoglobals
	New: func() any {
		b := make([]byte, inboundBufferSize)

		return &b
	},
}

func (c *Conn) readAndBuffer(ctx context.Context) error { //nolint:cyclop,gocognit
	bufptr, ok := poolReadBuffer.Get().(*[]byte)
	if !ok {
		return dtlserrors.ErrFailedToAccessPoolReadBuffer
	}
	defer poolReadBuffer.Put(bufptr)

	b := *bufptr
	i, rAddr, err := c.nextConn.ReadFromContext(ctx, b)
	if err != nil {
		return netError(err)
	}

	pkts, err := recordlayer.ContentAwareUnpackDatagram(b[:i], len(c.state.GetLocalConnectionID()))
	if err != nil {
		return err
	}

	var hasHandshake, isRetransmit bool
	for _, p := range pkts {
		//nolint:godox
		// TODO: check version
		hs, rtx, alert, err := c.handleIncomingPacket(ctx, p, rAddr, true)
		if alert != nil {
			if alertErr := c.notify(ctx, alert.Level, alert.Description); alertErr != nil {
				if err == nil {
					err = alertErr
				}
			}
		}

		var e *alertError
		if errors.As(err, &e) && e.IsFatalOrCloseNotify() {
			return e
		}
		if err != nil {
			return err
		}
		if hs {
			hasHandshake = true
		}
		if rtx {
			isRetransmit = true
		}
	}
	if hasHandshake {
		s := recvHandshakeState{
			done:         make(chan struct{}),
			isRetransmit: isRetransmit,
		}
		select {
		case c.handshakeRecv <- s:
			// If the other party may retransmit the flight,
			// we should respond even if it not a new message.
			<-s.done
		case <-c.fsm.Done():
		}
	}

	return nil
}

func (c *Conn) handleQueuedPackets(ctx context.Context) error {
	c.lock.Lock()
	pkts := c.encryptedPackets
	c.encryptedPackets = nil
	c.lock.Unlock()

	for _, p := range pkts {
		//nolint:godox
		// TODO: check version
		_, _, alert, err := c.handleIncomingPacket(ctx, p.data, p.rAddr, false) // don't re-enqueue
		if alert != nil {
			if alertErr := c.notify(ctx, alert.Level, alert.Description); alertErr != nil {
				if err == nil {
					err = alertErr
				}
			}
		}
		var e *alertError
		if errors.As(err, &e) && e.IsFatalOrCloseNotify() {
			return e
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Conn) enqueueEncryptedPackets(packet addrPkt) bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	if len(c.encryptedPackets) < maxAppDataPacketQueueSize {
		c.encryptedPackets = append(c.encryptedPackets, packet)

		return true
	}

	return false
}

// nolint:unused
func (c *Conn) handleIncomingPacket13(
	ctx context.Context,
	buf []byte,
	rAddr net.Addr,
	enqueue bool,
) (bool, bool, *alert.Alert, error) {
	// Placeholder function
	return false, false, nil, nil
}

//nolint:gocognit,gocyclo,cyclop,maintidx
func (c *Conn) handleIncomingPacket(
	ctx context.Context,
	buf []byte,
	rAddr net.Addr,
	enqueue bool,
) (bool, bool, *alert.Alert, error) {
	header := &recordlayer.Header{}
	// Set connection ID size so that records of content type tls12_cid will
	// be parsed correctly.
	if len(c.state.GetLocalConnectionID()) > 0 {
		header.ConnectionID = make([]byte, len(c.state.GetLocalConnectionID()))
	}
	if err := header.Unmarshal(buf); err != nil {
		// Decode error must be silently discarded
		// [RFC6347 Section-4.1.2.7]
		c.log.Debugf("discarded broken packet: %v", err)

		return false, false, nil, nil
	}
	// Validate epoch
	remoteEpoch := c.state.GetRemoteEpoch()
	if header.Epoch > remoteEpoch {
		if header.Epoch > remoteEpoch+1 {
			c.log.Debugf("discarded future packet (epoch: %d, seq: %d)",
				header.Epoch, header.SequenceNumber,
			)

			return false, false, nil, nil
		}
		if enqueue {
			if ok := c.enqueueEncryptedPackets(addrPkt{rAddr, buf}); ok {
				c.log.Debug("received packet of next epoch, queuing packet")
			}
		}

		return false, false, nil, nil
	}

	// Anti-replay protection
	for len(c.state.ReplayDetector) <= int(header.Epoch) {
		c.state.ReplayDetector = append(c.state.ReplayDetector,
			replaydetector.New(c.replayProtectionWindow, recordlayer.MaxSequenceNumber),
		)
	}
	markPacketAsValid, ok := c.state.ReplayDetector[int(header.Epoch)].Check(header.SequenceNumber)
	if !ok {
		c.log.Debugf("discarded duplicated packet (epoch: %d, seq: %d)",
			header.Epoch, header.SequenceNumber,
		)

		return false, false, nil, nil
	}

	// originalCID indicates whether the original record had content type
	// Connection ID.
	originalCID := false

	// Decrypt
	if header.Epoch != 0 { //nolint:nestif
		if c.state.CipherSuite == nil || !c.state.CipherSuite.IsInitialized() {
			if enqueue {
				if ok := c.enqueueEncryptedPackets(addrPkt{rAddr, buf}); ok {
					c.log.Debug("handshake not finished, queuing packet")
				}
			}

			return false, false, nil, nil
		}

		// If a connection identifier had been negotiated and encryption is
		// enabled, the connection identifier MUST be sent.
		if len(c.state.GetLocalConnectionID()) > 0 && header.ContentType != protocol.ContentTypeConnectionID {
			c.log.Debug("discarded packet missing connection ID after value negotiated")

			return false, false, nil, nil
		}

		var err error
		var hdr recordlayer.Header
		if header.ContentType == protocol.ContentTypeConnectionID {
			hdr.ConnectionID = make([]byte, len(c.state.GetLocalConnectionID()))
		}
		buf, err = c.state.CipherSuite.Decrypt(hdr, buf)
		if err != nil {
			c.log.Debugf("%s: decrypt failed: %s", srvCliStr(c.state.IsClient), err)

			return false, false, nil, nil
		}
		// If this is a connection ID record, make it look like a normal record for
		// further processing.
		if header.ContentType == protocol.ContentTypeConnectionID {
			originalCID = true
			ip := &recordlayer.InnerPlaintext{}
			if err := ip.Unmarshal(buf[header.Size():]); err != nil { //nolint:govet
				c.log.Debugf("unpacking inner plaintext failed: %s", err)

				return false, false, nil, nil
			}
			unpacked := &recordlayer.Header{
				ContentType:    ip.RealType,
				ContentLen:     uint16(len(ip.Content)), //nolint:gosec // G115
				Version:        header.Version,
				Epoch:          header.Epoch,
				SequenceNumber: header.SequenceNumber,
			}
			buf, err = unpacked.Marshal()
			if err != nil {
				c.log.Debugf("converting CID record to inner plaintext failed: %s", err)

				return false, false, nil, nil
			}
			buf = append(buf, ip.Content...)
		}

		// If connection ID does not match discard the packet.
		if !bytes.Equal(c.state.GetLocalConnectionID(), header.ConnectionID) {
			c.log.Debug("unexpected connection ID")

			return false, false, nil, nil
		}
	}

	isHandshake, isRetransmit, err := c.fragmentBuffer.push(append([]byte{}, buf...))
	if err != nil {
		// Decode error must be silently discarded
		// [RFC6347 Section-4.1.2.7]
		c.log.Debugf("defragment failed: %s", err)

		return false, false, nil, nil
	} else if isHandshake {
		markPacketAsValid()

		for out, epoch := c.fragmentBuffer.pop(); out != nil; out, epoch = c.fragmentBuffer.pop() {
			header := &handshake.Header{}
			if err := header.Unmarshal(out); err != nil {
				c.log.Debugf("%s: handshake parse failed: %s", srvCliStr(c.state.IsClient), err)

				continue
			}
			c.handshakeCache.Push(out, epoch, header.MessageSequence, header.Type, !c.state.IsClient)
		}

		return true, isRetransmit, nil, nil
	}

	r := &recordlayer.RecordLayer{}
	if err := r.Unmarshal(buf); err != nil {
		return false, false, &alert.Alert{Level: alert.Fatal, Description: alert.DecodeError}, err
	}

	isLatestSeqNum := false
	switch content := r.Content.(type) {
	case *alert.Alert:
		c.log.Tracef("%s: <- %s", srvCliStr(c.state.IsClient), content.String())
		var a *alert.Alert
		if content.Description == alert.CloseNotify {
			// Respond with a close_notify [RFC5246 Section 7.2.1]
			a = &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify}
		}
		_ = markPacketAsValid()

		return false, false, a, &alertError{content}
	case *protocol.ChangeCipherSpec:
		if c.state.CipherSuite == nil || !c.state.CipherSuite.IsInitialized() {
			if enqueue {
				if ok := c.enqueueEncryptedPackets(addrPkt{rAddr, buf}); ok {
					c.log.Debugf("CipherSuite not initialized, queuing packet")
				}
			}

			return false, false, nil, nil
		}

		newRemoteEpoch := header.Epoch + 1
		c.log.Tracef("%s: <- ChangeCipherSpec (epoch: %d)", srvCliStr(c.state.IsClient), newRemoteEpoch)

		if c.state.GetRemoteEpoch()+1 == newRemoteEpoch {
			c.setRemoteEpoch(newRemoteEpoch)
			isLatestSeqNum = markPacketAsValid()
		}
	case *protocol.ApplicationData:
		if header.Epoch == 0 {
			return false, false, &alert.Alert{
				Level: alert.Fatal, Description: alert.UnexpectedMessage,
			}, dtlserrors.ErrApplicationDataEpochZero
		}

		isLatestSeqNum = markPacketAsValid()

		select {
		case c.decrypted <- content.Data:
		case <-c.closed.Done():
		case <-ctx.Done():
		}

	default:
		return false, false, &alert.Alert{
			Level: alert.Fatal, Description: alert.UnexpectedMessage,
		}, fmt.Errorf("%w: %d", dtlserrors.ErrUnhandledContextType, content.ContentType())
	}

	// Any valid connection ID record is a candidate for updating the remote
	// address if it is the latest record received.
	// https://datatracker.ietf.org/doc/html/rfc9146#peer-address-update
	if originalCID && isLatestSeqNum {
		if rAddr != c.RemoteAddr() {
			c.lock.Lock()
			c.rAddr = rAddr
			c.lock.Unlock()
		}
	}

	return false, false, nil, nil
}

func (c *Conn) recvHandshake() <-chan recvHandshakeState {
	return c.handshakeRecv
}

func (c *Conn) notify(ctx context.Context, level alert.Level, desc alert.Description) error {
	if level == alert.Fatal && len(c.state.SessionID) > 0 { //nolint:nestif
		if c.state.LocalVersion == protocol.Version1_2 {
			// According to the RFC, we need to delete the stored session.
			// https://datatracker.ietf.org/doc/html/rfc5246#section-7.2
			cfg := c.fsm.(*handshakeFSM12).cfg //nolint:forcetypeassert
			if cfg.HasSessionStore {
				c.log.Tracef("clean invalid session: %s", c.state.SessionID)
				if err := cfg.DelSession(c.sessionKey()); err != nil {
					return err
				}
			}
		}
	}

	// This should be updated with DTLS 1.3 record encoding.
	return c.writePackets(ctx, []*dtlsflight.Packet{
		{
			Record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Epoch:   c.state.GetLocalEpoch(),
					Version: protocol.Version1_2,
				},
				Content: &alert.Alert{
					Level:       level,
					Description: desc,
				},
			},
			ShouldWrapCID: len(c.state.RemoteConnectionID) > 0,
			ShouldEncrypt: c.isHandshakeCompletedSuccessfully(),
		},
	})
}

func (c *Conn) setHandshakeCompletedSuccessfully() bool {
	return c.handshakeCompletedSuccessfully.CompareAndSwap(false, true)
}

func (c *Conn) isHandshakeCompletedSuccessfully() bool {
	return c.handshakeCompletedSuccessfully.Load()
}

func (c *Conn) negotiateVersionServer(ctx context.Context) error {
	for {
		if err := c.readAndBufferNoFSM(ctx); err != nil {
			return err
		}
		if ok, err := c.pickVersionFromClientHello(); err != nil {
			return err
		} else if ok {
			return nil
		}
		// ClientHello not yet (fully) received; keep reading.
	}
}

//nolint:cyclop
func (c *Conn) negotiateVersionClient(ctx context.Context) ([]*dtlsflight.Packet, *handshakeTranscript13, error) {
	transcript := newHandshakeTranscript13()
	gen, _, ok := dtlsflight13.GetGenerator(dtlsflight.Flight13_1)
	if !ok {
		return nil, nil, dtlserrors.ErrFlightUnimplemented13
	}
	pkts, dtlsAlert, err := gen(adaptFlightConn(c), &c.state, c.handshakeCache, c.handshakeConfig)
	if dtlsAlert != nil {
		if alertErr := c.notify(ctx, dtlsAlert.Level, dtlsAlert.Description); alertErr != nil && err == nil {
			err = alertErr
		}
	}
	if err != nil {
		return nil, nil, err
	}

	c.stampHandshakeSequence(pkts)
	if appended, err := appendClientHelloInitialFlights13(transcript, pkts); err != nil {
		return nil, nil, err
	} else if !appended {
		return nil, nil, dtlserrors.ErrHandshakeTranscriptMissingClientHello
	}
	if err := c.writePackets(ctx, pkts); err != nil {
		return nil, nil, err
	}

	for {
		if err := c.readAndBufferNoFSM(ctx); err != nil {
			return nil, nil, err
		}
		if ok, err := c.pickVersionFromServerResponse(); err != nil {
			return nil, nil, err
		} else if ok {
			return pkts, transcript, nil
		}
		// ServerHello or HelloVerifyRequest not yet (fully) received; keep reading.
	}
}

// pickVersionFromClientHello inspects the handshake cache for incoming
// ClientHello and, if found, sets localVersion and remoteVersions.
// Returns true once the version can be decided.
func (c *Conn) pickVersionFromClientHello() (bool, error) {
	_, msgs, ok := c.handshakeCache.FullPullMap(0, c.state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: c.handshakeConfig.InitialEpoch, IsClient: true, Optional: false}, //nolint:lll
	)
	if !ok {
		return false, nil
	}
	ch, ok := msgs[handshake.TypeClientHello].(*handshake.MessageClientHello)
	if !ok {
		return false, nil
	}

	var remote []protocol.Version
	seenSupportedVersions := false
	for _, e := range ch.Extensions {
		if sv, ok := e.(*extension.SupportedVersions); ok { //nolint:govet
			seenSupportedVersions = true
			remote = sv.Versions

			break
		}
	}
	if !seenSupportedVersions {
		remote = []protocol.Version{ch.Version}
	}

	chosen, ok := selectVersion(remote, c.handshakeConfig.MinVersion, c.handshakeConfig.MaxVersion)
	if !ok {
		return false, dtlserrors.ErrNoCommonProtocolVersion
	}

	c.state.RemoteVersions = remote
	c.state.LocalVersion = chosen

	return true, nil
}

// pickVersionFromServerResponse inspects the handshake cache for the server's
// response to our ClientHello and, if found, sets localVersion and
// remoteVersions. Returns true once the version can be pinned down.
//
// Handling:
//   - ServerHello with supported_versions: finds match (1.2 or 1.3).
//   - ServerHello without supported_versions: fall back to ServerHello.Version.
//   - HelloVerifyRequest (1.2 cookie request): version is 1.2.
func (c *Conn) pickVersionFromServerResponse() (bool, error) {
	if sh, ok := c.findCachedServerMessage(handshake.TypeServerHello).(*handshake.MessageServerHello); ok {
		if err := c.pickVersionFromServerHello(sh); err != nil {
			return false, err
		}

		return true, nil
	}

	if hvr, ok := c.findCachedServerMessage(handshake.TypeHelloVerifyRequest).(*handshake.MessageHelloVerifyRequest); ok {
		if err := c.pickVersionFromHelloVerifyRequest(hvr); err != nil {
			return false, err
		}

		return true, nil
	}

	return false, nil
}

func (c *Conn) pickVersionFromServerHello(sh *handshake.MessageServerHello) error {
	remote, err := remoteVersionsFromServerHello(sh)
	if err != nil {
		return err
	}

	return c.selectRemoteVersion(remote)
}

func (c *Conn) pickVersionFromHelloVerifyRequest(hvr *handshake.MessageHelloVerifyRequest) error {
	c.state.LocalVersion = protocol.Version1_2

	return c.selectRemoteVersion([]protocol.Version{hvr.Version})
}

func remoteVersionsFromServerHello(sh *handshake.MessageServerHello) ([]protocol.Version, error) {
	remote, seenSupportedVersions, err := dtlsflight13.ServerHelloSelectedVersions(sh.Extensions)
	if dtlsflight13.IsHelloRetryRequest(sh) {
		return remoteVersionsFromHelloRetryRequest(remote, seenSupportedVersions, err)
	}
	if err != nil {
		return nil, err
	}
	if !seenSupportedVersions {
		return []protocol.Version{sh.Version}, nil
	}

	return remote, nil
}

func remoteVersionsFromHelloRetryRequest(
	remote []protocol.Version,
	seenSupportedVersions bool,
	err error,
) ([]protocol.Version, error) {
	if err != nil || !seenSupportedVersions {
		return nil, dtlserrors.ErrInvalidHelloRetryRequest
	}
	if !remote[0].Equal(protocol.Version1_3) {
		return nil, dtlserrors.ErrUnsupportedProtocolVersion
	}

	return remote, nil
}

func (c *Conn) selectRemoteVersion(remote []protocol.Version) error {
	chosen, ok := selectVersion(remote, c.handshakeConfig.MinVersion, c.handshakeConfig.MaxVersion)
	if !ok {
		return dtlserrors.ErrNoCommonProtocolVersion
	}
	c.state.RemoteVersions = remote
	c.state.LocalVersion = chosen

	return nil
}

// findCachedServerMessage pulls the most recent handshake message of the
// given type sent by the peer from the cache, if any.
func (c *Conn) findCachedServerMessage(messageType handshake.Type) handshake.Message {
	_, msgs, ok := c.handshakeCache.FullPullMap(0, c.state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: messageType, Epoch: c.handshakeConfig.InitialEpoch, IsClient: false, Optional: true}, //nolint:lll
	)
	if !ok {
		return nil
	}

	return msgs[messageType]
}

// stampHandshakeSequence assigns the DTLS message_sequence to each handshake
// record in pkts, using and advancing state.handshakeSendSequence. This is
// the subset of handshakeFSM.prepare()'s bookkeeping that generated dual-stack
// packets need before being passed to writePackets.
func (c *Conn) stampHandshakeSequence(pkts []*dtlsflight.Packet) {
	epoch := c.handshakeConfig.InitialEpoch
	for _, p := range pkts {
		p.Record.Header.Epoch += epoch
		if h, ok := p.Record.Content.(*handshake.Handshake); ok {
			h.Header.MessageSequence = uint16(c.state.HandshakeSendSequence) //nolint:gosec // G115
			c.state.HandshakeSendSequence++
		}
	}
}

// primeHandshakeRecv sends a single recvHandshakeState to the FSM so that its
// wait state parses messages already pushed into handshakeCache during the
// dual-stack version negotiation mode. Without this, the FSM would block until
// its retransmit timer fires, since readAndBufferNoFSM does not signal.
// The send blocks until the FSM reaches wait() or the handshake is torn down.
func (c *Conn) primeHandshakeRecv(ctx context.Context) {
	s := recvHandshakeState{
		done:         make(chan struct{}),
		isRetransmit: false,
	}
	select {
	case c.handshakeRecv <- s:
		select {
		case <-s.done:
		case <-ctx.Done():
		case <-c.fsm.Done():
		}
	case <-ctx.Done():
	case <-c.fsm.Done():
	}
}

// readAndBufferNoFSM is a variant of readAndBuffer used during the dual-stack
// version negotiation phase. It reads a datagram and pushes any handshake
// fragments into handshakeCache, but does not signal an FSM (there is none
// yet) or wait for its Done channel.
func (c *Conn) readAndBufferNoFSM(ctx context.Context) error { //nolint:cyclop
	bufptr, ok := poolReadBuffer.Get().(*[]byte)
	if !ok {
		return dtlserrors.ErrFailedToAccessPoolReadBuffer
	}
	defer poolReadBuffer.Put(bufptr)

	b := *bufptr
	i, rAddr, err := c.nextConn.ReadFromContext(ctx, b)
	if err != nil {
		return netError(err)
	}

	pkts, err := recordlayer.ContentAwareUnpackDatagram(b[:i], len(c.state.GetLocalConnectionID()))
	if err != nil {
		return err
	}

	for _, p := range pkts {
		// nolint:godox
		// TODO: check version
		_, _, alert, err := c.handleIncomingPacket(ctx, p, rAddr, true)
		if alert != nil {
			if alertErr := c.notify(ctx, alert.Level, alert.Description); alertErr != nil {
				if err == nil {
					err = alertErr
				}
			}
		}

		var e *alertError
		if errors.As(err, &e) && e.IsFatalOrCloseNotify() {
			return e
		}
		if err != nil {
			return err
		}
	}

	return nil
}

//nolint:gocyclo,cyclop,gocognit,contextcheck
func (c *Conn) handshake(ctx context.Context, start handshakeStart) error {
	done := make(chan struct{})
	if c.state.LocalVersion == protocol.Version1_3 {
		fsm, err := newHandshakeFSM13(
			&c.state,
			c.handshakeCache,
			c.handshakeConfig,
			start.flight13,
			start.flights,
			start.transcript13,
		)
		if err != nil {
			return err
		}
		c.fsm = fsm
		c.handshakeConfig.OnFlightState13 = func(_ uint8, s uint8) {
			// The ACK for the last flights has been received and we are in a Finished state.
			// nolint:godox
			// TODO: should be moved to FSM.
			if handshakeState(s) == handshakeFinished && c.setHandshakeCompletedSuccessfully() {
				close(done)
			}
		}
	} else {
		c.fsm = &handshakeFSM12{
			currentFlight:      start.flight12,
			flights:            start.flights,
			retransmit:         start.flights != nil,
			state:              &c.state,
			cache:              c.handshakeCache,
			cfg:                c.handshakeConfig,
			retransmitInterval: c.handshakeConfig.InitialRetransmitInterval,
			closed:             make(chan struct{}),
		}
		c.handshakeConfig.OnFlightState = func(_ uint8, s uint8) {
			if handshakeState(s) == handshakeFinished && c.setHandshakeCompletedSuccessfully() {
				close(done)
			}
		}
	}

	ctxRead, cancelRead := context.WithCancel(context.Background())
	ctxHs, cancel := context.WithCancel(context.Background())

	c.closeLock.Lock()
	c.cancelHandshaker = cancel
	c.cancelHandshakeReader = cancelRead
	c.closeLock.Unlock()

	firstErr := make(chan error, 1)

	var handshakeLoopsFinished sync.WaitGroup
	handshakeLoopsFinished.Add(2)

	// Handshake routine should be live until close.
	// The other party may request retransmission of the last flight to cope with packet drop.
	go func() {
		defer handshakeLoopsFinished.Done()
		err := c.fsm.Run(ctxHs, c, start.fsmState)
		if !errors.Is(err, context.Canceled) {
			select {
			case firstErr <- err:
			default:
			}
		}
	}()

	if start.postSetup != nil {
		start.postSetup(ctxHs)
	}

	go func() {
		defer func() {
			if c.isHandshakeCompletedSuccessfully() {
				// Escaping read loop.
				// It's safe to close decrypted channnel now.
				close(c.decrypted)
			}

			// Force stop handshaker when the underlying connection is closed.
			cancel()
		}()
		defer handshakeLoopsFinished.Done()
		for {
			if err := c.readAndBuffer(ctxRead); err != nil { //nolint:nestif
				var alertErr *alertError
				if errors.As(err, &alertErr) {
					if !alertErr.IsFatalOrCloseNotify() {
						if c.isHandshakeCompletedSuccessfully() {
							// Pass the error to Read()
							select {
							case c.decrypted <- err:
							case <-c.closed.Done():
							case <-ctxRead.Done():
							}
						}

						continue // non-fatal alert must not stop read loop
					}
				} else {
					switch {
					case errors.Is(err, context.DeadlineExceeded),
						errors.Is(err, context.Canceled),
						errors.Is(err, io.EOF),
						errors.Is(err, net.ErrClosed):
					case errors.Is(err, recordlayer.ErrInvalidPacketLength):
						// Decode error must be silently discarded
						// [RFC6347 Section-4.1.2.7]
						continue
					default:
						if c.isHandshakeCompletedSuccessfully() {
							// Keep read loop and pass the read error to Read()
							select {
							case c.decrypted <- err:
							case <-c.closed.Done():
							case <-ctxRead.Done():
							}

							continue // non-fatal alert must not stop read loop
						}
					}
				}

				select {
				case firstErr <- err:
				default:
				}

				if alertErr != nil {
					if alertErr.IsFatalOrCloseNotify() {
						_ = c.close(false) //nolint:contextcheck
					}
				}
				if !c.isConnectionClosed() && errors.Is(err, context.Canceled) {
					c.log.Trace("handshake timeouts - closing underline connection")
					_ = c.close(false) //nolint:contextcheck
				}

				return
			}
		}
	}()

	select {
	case err := <-firstErr:
		cancelRead()
		cancel()
		handshakeLoopsFinished.Wait()

		return c.translateHandshakeCtxError(err)
	case <-ctx.Done():
		cancelRead()
		cancel()
		handshakeLoopsFinished.Wait()

		return c.translateHandshakeCtxError(ctx.Err())
	case <-done:
		return nil
	}
}

func (c *Conn) translateHandshakeCtxError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) && c.isHandshakeCompletedSuccessfully() {
		return nil
	}

	return fmt.Errorf("handshake failed: %w", err)
}

func (c *Conn) close(byUser bool) error {
	c.closeLock.Lock()
	cancelHandshaker := c.cancelHandshaker
	cancelHandshakeReader := c.cancelHandshakeReader
	c.closeLock.Unlock()

	cancelHandshaker()
	cancelHandshakeReader()

	if c.isHandshakeCompletedSuccessfully() && byUser {
		// Discard error from notify() to return non-error on the first user call of Close()
		// even if the underlying connection is already closed.
		_ = c.notify(context.Background(), alert.Warning, alert.CloseNotify)
	}

	c.closeLock.Lock()
	// Don't return ErrConnClosed at the first time of the call from user.
	closedByUser := c.connectionClosedByUser
	if byUser {
		c.connectionClosedByUser = true
	}
	isClosed := c.isConnectionClosed()
	c.closed.Close()
	c.closeLock.Unlock()

	if closedByUser {
		return ErrConnClosed
	}

	if isClosed {
		return nil
	}

	return c.nextConn.Close()
}

func (c *Conn) isConnectionClosed() bool {
	select {
	case <-c.closed.Done():
		return true
	default:
		return false
	}
}

func (c *Conn) setLocalEpoch(epoch uint16) {
	c.state.LocalEpoch.Store(epoch)
}

func (c *Conn) setRemoteEpoch(epoch uint16) {
	c.state.RemoteEpoch.Store(epoch)
}

// LocalAddr implements net.Conn.LocalAddr.
func (c *Conn) LocalAddr() net.Addr {
	return c.nextConn.LocalAddr()
}

// RemoteAddr implements net.Conn.RemoteAddr.
func (c *Conn) RemoteAddr() net.Addr {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.rAddr
}

func (c *Conn) sessionKey() []byte {
	if c.state.IsClient {
		// As ServerName can be like 0.example.com, it's better to add
		// delimiter character which is not allowed to be in
		// neither address or domain name.
		if c.state.LocalVersion == protocol.Version1_3 {
			return []byte(c.rAddr.String() + "_" + c.fsm.(*handshakeFSM13).cfg.ServerName) //nolint:forcetypeassert
		}

		return []byte(c.rAddr.String() + "_" + c.fsm.(*handshakeFSM12).cfg.ServerName) //nolint:forcetypeassert
	}

	return c.state.SessionID
}

// SetDeadline implements net.Conn.SetDeadline.
func (c *Conn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)

	return c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn.SetReadDeadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	// Read deadline is fully managed by this layer.
	// Don't set read deadline to underlying connection.
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	// Write deadline is also fully managed by this layer.
	return nil
}
