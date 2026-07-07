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

	"github.com/pion/dtls/v3/internal/ciphersuite"
	"github.com/pion/dtls/v3/internal/closer"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight12 "github.com/pion/dtls/v3/internal/flight/flight12"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlshandshake "github.com/pion/dtls/v3/internal/handshake"
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

type incomingPacketState struct {
	buf               []byte
	header            *recordlayer.Header
	markPacketAsValid func() bool
	originalCID       bool
}

type handshakeStart struct {
	flight12  dtlsflight12.Flight
	flight13  dtlsflight13.Flight
	fsmState  handshakeState
	flights   []*dtlsflight.Packet
	postSetup func(context.Context)
}

type (
	handshakeConfig = dtlsconfig.HandshakeConfig
	handshakeState  = dtlshandshake.State
)

const (
	handshakeErrored   = dtlshandshake.StateErrored
	handshakePreparing = dtlshandshake.StatePreparing
	handshakeSending   = dtlshandshake.StateSending
	handshakeWaiting   = dtlshandshake.StateWaiting
	handshakeFinished  = dtlshandshake.StateFinished
)

type (
	recvHandshakeState = dtlshandshake.RecvHandshakeState
	handshakeFSM       = dtlshandshake.FSM
)

type handshakeConn interface {
	notify(ctx context.Context, level alert.Level, desc alert.Description) error
	writePackets(context.Context, []*dtlsflight.Packet) error
	recvHandshake() <-chan recvHandshakeState
	setLocalEpoch(epoch uint16)
	handleQueuedPackets(context.Context) error
	sessionKey() []byte
}

type handshakeConnAdapter struct {
	handshakeConn
}

func (c handshakeConnAdapter) Notify(ctx context.Context, level alert.Level, desc alert.Description) error {
	return c.notify(ctx, level, desc)
}

func (c handshakeConnAdapter) WritePackets(ctx context.Context, pkts []*dtlsflight.Packet) error {
	return c.writePackets(ctx, pkts)
}

func (c handshakeConnAdapter) RecvHandshake() <-chan recvHandshakeState {
	return c.recvHandshake()
}

func (c handshakeConnAdapter) SetLocalEpoch(epoch uint16) {
	c.setLocalEpoch(epoch)
}

func (c handshakeConnAdapter) HandleQueuedPackets(ctx context.Context) error {
	return c.handleQueuedPackets(ctx)
}

func (c handshakeConnAdapter) SessionKey() []byte {
	return c.sessionKey()
}

func adaptFlightConn(conn handshakeConn) dtlsflight.Conn {
	if conn == nil {
		return nil
	}

	return handshakeConnAdapter{conn}
}

func srvCliStr(isClient bool) string {
	if isClient {
		return "client"
	}

	return "server"
}

type connConfigValues struct {
	logger                      logging.LeveledLogger
	maximumTransmissionUnit     int
	paddingLengthGenerator      func(uint) uint
	replayProtectionWindow      int
	initialRetransmitInterval   time.Duration
	minVersion                  protocol.Version
	maxVersion                  protocol.Version
	cipherSuites                []dtlsconfig.CipherSuite
	signatureSchemes            []signaturehash.Algorithm
	certificateSignatureSchemes []signaturehash.Algorithm
	ellipticCurves              []elliptic.Curve
	serverName                  string
}

type connConfigCallbacks struct {
	customCipherSuites   func() []dtlsconfig.CipherSuite
	verifyConnection     func(*dtlsstate.State) error
	getCertificate       func(*dtlsconfig.ClientHelloInfo) (*tls.Certificate, error)
	getClientCertificate func(*dtlsconfig.CertificateRequestInfo) (*tls.Certificate, error)
}

type connSessionCallbacks struct {
	getSession func(key []byte) (id, secret []byte, err error)
	setSession func(key, id, secret []byte) error
	delSession func(key []byte) error
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
	writeLock                      sync.Mutex

	encryptedPackets []addrPkt

	connectionClosedByUser bool
	closeLock              sync.Mutex
	closed                 *closer.Closer

	readDeadline  *deadline.Deadline
	writeDeadline *deadline.Deadline

	log logging.LeveledLogger

	reading               chan struct{}
	handshakeRecv         chan dtlshandshake.RecvHandshakeState
	cancelHandshaker      func()
	cancelHandshakeReader func()

	fsm handshakeFSM

	replayProtectionWindow uint

	handshakeConfig *handshakeConfig
}

// createConn creates a new DTLS connection.
// Caller is responsible for validating the config before calling this function.
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

	configValues, err := newConnConfigValues(config)
	if err != nil {
		return nil, err
	}

	callbacks := newConnConfigCallbacks(config)
	sessions := newConnSessionCallbacks(config.sessionStore)
	handshakeConfig := newHandshakeConfig(config, configValues, callbacks, sessions, resumeState)
	conn := newConn(nextConn, rAddr, configValues, handshakeConfig, isClient)

	conn.setRemoteEpoch(0)
	conn.setLocalEpoch(0)

	return conn, nil
}

func newConnConfigValues(config *dtlsConfig) (connConfigValues, error) {
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
		return connConfigValues{}, err
	}

	signatureSchemes, certSignatureSchemes, err := parseConnSignatureSchemes(config)
	if err != nil {
		return connConfigValues{}, err
	}

	return connConfigValues{
		logger:                      newConnLogger(config),
		maximumTransmissionUnit:     effectiveMTU(config.MTU),
		paddingLengthGenerator:      effectivePaddingLengthGenerator(config.PaddingLengthGenerator),
		replayProtectionWindow:      effectiveReplayProtectionWindow(config.ReplayProtectionWindow),
		initialRetransmitInterval:   effectiveFlightInterval(config.FlightInterval),
		minVersion:                  minVersion,
		maxVersion:                  maxVersion,
		cipherSuites:                cipherSuites,
		signatureSchemes:            signatureSchemes,
		certificateSignatureSchemes: certSignatureSchemes,
		ellipticCurves:              effectiveEllipticCurves(config.EllipticCurves),
		serverName:                  effectiveServerName(config.ServerName),
	}, nil
}

func parseConnSignatureSchemes(
	config *dtlsConfig,
) ([]signaturehash.Algorithm, []signaturehash.Algorithm, error) {
	signatureSchemes, err := signaturehash.ParseSignatureSchemes(config.SignatureSchemes, config.InsecureHashes)
	if err != nil {
		return nil, nil, err
	}

	var certSignatureSchemes []signaturehash.Algorithm
	if len(config.CertificateSignatureSchemes) > 0 {
		certSignatureSchemes, err = signaturehash.ParseSignatureSchemes(
			config.CertificateSignatureSchemes,
			config.InsecureHashes,
		)
		if err != nil {
			return nil, nil, err
		}
	}

	return signatureSchemes, certSignatureSchemes, nil
}

func newConnLogger(config *dtlsConfig) logging.LeveledLogger {
	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	return loggerFactory.NewLogger("dtls")
}

func effectiveMTU(mtu int) int {
	if mtu <= 0 {
		return defaultMTU
	}

	return mtu
}

func effectiveReplayProtectionWindow(replayProtectionWindow int) int {
	if replayProtectionWindow <= 0 {
		return defaultReplayProtectionWindow
	}

	return replayProtectionWindow
}

func effectivePaddingLengthGenerator(generator func(uint) uint) func(uint) uint {
	if generator == nil {
		return func(uint) uint { return 0 }
	}

	return generator
}

func effectiveFlightInterval(flightInterval time.Duration) time.Duration {
	if flightInterval <= 0 {
		return initialTickerInterval
	}

	return flightInterval
}

func effectiveServerName(serverName string) string {
	// Do not allow the use of an IP address literal as an SNI value.
	// See RFC 6066, Section 3.
	if net.ParseIP(serverName) != nil {
		return ""
	}

	return serverName
}

func effectiveEllipticCurves(curves []elliptic.Curve) []elliptic.Curve {
	if len(curves) == 0 {
		curves = defaultCurves
	}
	if !fips140.Enabled() {
		return curves
	}

	return filterFIPSCurves(curves)
}

func filterFIPSCurves(curves []elliptic.Curve) []elliptic.Curve {
	filtered := make([]elliptic.Curve, 0, len(curves))
	for _, curve := range curves {
		if curve != elliptic.X25519 && curve != elliptic.X25519MLKEM768 {
			filtered = append(filtered, curve)
		}
	}

	return filtered
}

func newConnConfigCallbacks(config *dtlsConfig) connConfigCallbacks {
	return connConfigCallbacks{
		customCipherSuites:   adaptCustomCipherSuites(config.customCipherSuites),
		verifyConnection:     adaptVerifyConnection(config.verifyConnection),
		getCertificate:       adaptGetCertificate(config.getCertificate),
		getClientCertificate: adaptGetClientCertificate(config.getClientCertificate),
	}
}

func adaptCustomCipherSuites(customCipherSuites func() []CipherSuite) func() []dtlsconfig.CipherSuite {
	if customCipherSuites == nil {
		return nil
	}

	return func() []dtlsconfig.CipherSuite {
		return toConfigCipherSuites(customCipherSuites())
	}
}

func adaptVerifyConnection(verifyConnection func(*State) error) func(*dtlsstate.State) error {
	if verifyConnection == nil {
		return nil
	}

	return func(state *dtlsstate.State) error {
		stateSnapshot, err := generateState(state)
		if err != nil {
			return err
		}

		return verifyConnection(stateSnapshot)
	}
}

func adaptGetCertificate(
	getCertificate func(*ClientHelloInfo) (*tls.Certificate, error),
) func(*dtlsconfig.ClientHelloInfo) (*tls.Certificate, error) {
	if getCertificate == nil {
		return nil
	}

	return func(info *dtlsconfig.ClientHelloInfo) (*tls.Certificate, error) {
		return getCertificate(&ClientHelloInfo{
			ServerName:   info.ServerName,
			CipherSuites: info.CipherSuites,
			RandomBytes:  info.RandomBytes,
		})
	}
}

func adaptGetClientCertificate(
	getClientCertificate func(*CertificateRequestInfo) (*tls.Certificate, error),
) func(*dtlsconfig.CertificateRequestInfo) (*tls.Certificate, error) {
	if getClientCertificate == nil {
		return nil
	}

	return func(info *dtlsconfig.CertificateRequestInfo) (*tls.Certificate, error) {
		return getClientCertificate(&CertificateRequestInfo{AcceptableCAs: info.AcceptableCAs})
	}
}

func newConnSessionCallbacks(sessionStore SessionStore) connSessionCallbacks {
	return connSessionCallbacks{
		getSession: func(key []byte) (id, secret []byte, err error) {
			session, err := sessionStore.Get(key)

			return session.ID, session.Secret, err
		},
		setSession: func(key, id, secret []byte) error {
			return sessionStore.Set(key, Session{ID: id, Secret: secret})
		},
		delSession: func(key []byte) error {
			return sessionStore.Del(key)
		},
	}
}

func newHandshakeConfig(
	config *dtlsConfig,
	configValues connConfigValues,
	callbacks connConfigCallbacks,
	sessions connSessionCallbacks,
	resumeState *dtlsstate.State,
) *handshakeConfig {
	handshakeConfig := &handshakeConfig{
		Log:          configValues.logger,
		InitialEpoch: 0,
		ResumeState:  resumeState,
	}

	setHandshakeConfigCrypto(handshakeConfig, config, configValues)
	setHandshakeConfigIdentity(handshakeConfig, config, configValues, callbacks)
	setHandshakeConfigSession(handshakeConfig, config, sessions)
	setHandshakeConfigTransport(handshakeConfig, config, configValues, callbacks)
	setHandshakeConfigHooks(handshakeConfig, config)

	return handshakeConfig
}

func setHandshakeConfigCrypto(
	handshakeConfig *handshakeConfig,
	config *dtlsConfig,
	configValues connConfigValues,
) {
	handshakeConfig.LocalPSKCallback = config.psk
	handshakeConfig.LocalPSKIdentityHint = config.PSKIdentityHint
	handshakeConfig.LocalCipherSuites = configValues.cipherSuites
	handshakeConfig.LocalSignatureSchemes = configValues.signatureSchemes
	handshakeConfig.LocalCertSignatureSchemes = configValues.certificateSignatureSchemes
	handshakeConfig.ExtendedMasterSecret = dtlsconfig.ExtendedMasterSecretType(config.ExtendedMasterSecret)
	handshakeConfig.LocalCertificates = config.Certificates
	handshakeConfig.RootCAs = config.RootCAs
	handshakeConfig.ClientCAs = config.ClientCAs
	handshakeConfig.EllipticCurves = configValues.ellipticCurves
}

func setHandshakeConfigIdentity(
	handshakeConfig *handshakeConfig,
	config *dtlsConfig,
	configValues connConfigValues,
	callbacks connConfigCallbacks,
) {
	handshakeConfig.ServerName = configValues.serverName
	handshakeConfig.SupportedProtocols = config.SupportedProtocols
	handshakeConfig.ClientAuth = dtlsconfig.ClientAuthType(config.ClientAuth)
	handshakeConfig.InsecureSkipVerify = config.InsecureSkipVerify
	handshakeConfig.VerifyPeerCertificate = config.VerifyPeerCertificate
	handshakeConfig.VerifyConnection = callbacks.verifyConnection
	handshakeConfig.LocalGetCertificate = callbacks.getCertificate
	handshakeConfig.LocalGetClientCertificate = callbacks.getClientCertificate
}

func setHandshakeConfigSession(
	handshakeConfig *handshakeConfig,
	config *dtlsConfig,
	sessions connSessionCallbacks,
) {
	handshakeConfig.HasSessionStore = config.sessionStore != nil
	handshakeConfig.GetSession = sessions.getSession
	handshakeConfig.SetSession = sessions.setSession
	handshakeConfig.DelSession = sessions.delSession
}

func setHandshakeConfigTransport(
	handshakeConfig *handshakeConfig,
	config *dtlsConfig,
	configValues connConfigValues,
	callbacks connConfigCallbacks,
) {
	handshakeConfig.LocalSRTPProtectionProfiles = config.SRTPProtectionProfiles
	handshakeConfig.LocalSRTPMasterKeyIdentifier = config.SRTPMasterKeyIdentifier
	handshakeConfig.CustomCipherSuites = callbacks.customCipherSuites
	handshakeConfig.InitialRetransmitInterval = configValues.initialRetransmitInterval
	handshakeConfig.DisableRetransmitBackoff = config.DisableRetransmitBackoff
	handshakeConfig.KeyLogWriter = config.KeyLogWriter
	handshakeConfig.InsecureSkipHelloVerify = config.InsecureSkipVerifyHello
	handshakeConfig.ConnectionIDGenerator = config.ConnectionIDGenerator
	handshakeConfig.HelloRandomBytesGenerator = config.HelloRandomBytesGenerator
	handshakeConfig.MinVersion = configValues.minVersion
	handshakeConfig.MaxVersion = configValues.maxVersion
}

func setHandshakeConfigHooks(handshakeConfig *handshakeConfig, config *dtlsConfig) {
	handshakeConfig.ClientHelloMessageHook = config.ClientHelloMessageHook
	handshakeConfig.ServerHelloMessageHook = config.ServerHelloMessageHook
	handshakeConfig.CertificateRequestMessageHook = config.CertificateRequestMessageHook
}

func newConn(
	nextConn net.PacketConn,
	rAddr net.Addr,
	configValues connConfigValues,
	handshakeConfig *handshakeConfig,
	isClient bool,
) *Conn {
	return &Conn{
		rAddr:                   rAddr,
		nextConn:                netctx.NewPacketConn(nextConn),
		handshakeConfig:         handshakeConfig,
		fragmentBuffer:          newFragmentBuffer(),
		handshakeCache:          dtlsflight.NewCache(),
		maximumTransmissionUnit: configValues.maximumTransmissionUnit,
		paddingLengthGenerator:  configValues.paddingLengthGenerator,

		decrypted: make(chan any, 1),
		log:       configValues.logger,

		readDeadline:  deadline.New(),
		writeDeadline: deadline.New(),

		reading:               make(chan struct{}, 1),
		handshakeRecv:         make(chan dtlshandshake.RecvHandshakeState),
		closed:                closer.NewCloser(),
		cancelHandshaker:      func() {},
		cancelHandshakeReader: func() {},

		replayProtectionWindow: uint(configValues.replayProtectionWindow), //nolint:gosec // G115

		state: dtlsstate.State{
			IsClient: isClient,
		},
	}
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
// In dual-stack client mode, flights holds the already-sent ClientHello. If
// DTLS 1.3 is selected, the DTLS 1.3 FSM imports those packets into its
// transcript.
func (c *Conn) prepareHandshakeStart(ctx context.Context) (handshakeStart, error) {
	if c.handshakeConfig.MaxVersion == protocol.Version1_2 {
		return c.prepareHandshakeStart12(), nil
	}
	if c.handshakeConfig.MinVersion == protocol.Version1_3 {
		return c.prepareHandshakeStart13(), nil
	}
	if c.state.IsClient {
		return c.prepareDualStackClientHandshakeStart(ctx)
	}

	return c.prepareDualStackServerHandshakeStart(ctx)
}

func (c *Conn) prepareHandshakeStart12() handshakeStart {
	isClient := c.state.IsClient
	c.state.LocalVersion = protocol.Version1_2
	if c.handshakeConfig.ResumeState != nil {
		c.state = *c.handshakeConfig.ResumeState
		c.state.LocalVersion = protocol.Version1_2

		if isClient {
			return handshakeStart{flight12: dtlsflight12.Flight5, fsmState: handshakeFinished}
		}

		return handshakeStart{flight12: dtlsflight12.Flight6, fsmState: handshakeFinished}
	}

	if isClient {
		return handshakeStart{flight12: dtlsflight12.Flight1, fsmState: handshakePreparing}
	}

	return handshakeStart{flight12: dtlsflight12.Flight0, fsmState: handshakePreparing}
}

func (c *Conn) prepareHandshakeStart13() handshakeStart {
	c.state.LocalVersion = protocol.Version1_3
	if c.state.IsClient {
		return handshakeStart{flight13: dtlsflight13.Flight1, fsmState: handshakePreparing}
	}

	return handshakeStart{flight13: dtlsflight13.Flight0, fsmState: handshakePreparing}
}

func (c *Conn) prepareDualStackClientHandshakeStart(ctx context.Context) (handshakeStart, error) {
	initialFlights, err := c.negotiateVersionClient(ctx)
	if err != nil {
		return handshakeStart{}, err
	}

	return handshakeStart{
		flight12: dtlsflight12.Flight1,
		flight13: dtlsflight13.Flight1,
		fsmState: handshakeWaiting,
		flights:  initialFlights,
		postSetup: func(ctx context.Context) {
			go c.primeHandshakeRecv(ctx)
		},
	}, nil
}

func (c *Conn) prepareDualStackServerHandshakeStart(ctx context.Context) (handshakeStart, error) {
	err := c.negotiateVersionServer(ctx)
	if err != nil {
		return handshakeStart{}, err
	}

	return handshakeStart{
		flight12: dtlsflight12.Flight0,
		flight13: dtlsflight13.Flight0,
		fsmState: handshakePreparing,
	}, nil
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
		case <-c.closed.Done():
			return 0, io.EOF
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
	ctx, cancel := c.contextWithClose(c.writeDeadline)
	defer cancel()

	return len(payload), c.writePackets(ctx, []*dtlsflight.Packet{
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
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	compactedRawPackets, rAddr, err := c.prepareRawPackets(pkts)
	if err != nil {
		return err
	}

	for _, compactedRawPacket := range compactedRawPackets {
		if _, err = c.nextConn.WriteToContext(ctx, compactedRawPacket, rAddr); err != nil {
			if errors.Is(err, context.Canceled) && c.isConnectionClosed() {
				return ErrConnClosed
			}

			return netError(err)
		}
	}

	return nil
}

func (c *Conn) prepareRawPackets(pkts []*dtlsflight.Packet) ([][]byte, net.Addr, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	var rawPackets [][]byte

	for _, pkt := range pkts {
		pktRawPackets, err := c.prepareRawPacket(pkt)
		if err != nil {
			return nil, nil, err
		}

		rawPackets = append(rawPackets, pktRawPackets...)
	}
	if len(rawPackets) == 0 {
		return nil, nil, nil
	}

	return c.compactRawPackets(rawPackets), c.rAddr, nil
}

func (c *Conn) prepareRawPacket(pkt *dtlsflight.Packet) ([][]byte, error) {
	dtlsHandshake, ok := pkt.Record.Content.(*handshake.Handshake)
	if ok {
		if err := c.cacheHandshakePacket(pkt, dtlsHandshake); err != nil {
			return nil, err
		}

		return c.processHandshakePacket(pkt, dtlsHandshake)
	}

	rawPacket, err := c.processPacket(pkt)
	if err != nil {
		return nil, err
	}

	return [][]byte{rawPacket}, nil
}

func (c *Conn) cacheHandshakePacket(pkt *dtlsflight.Packet, dtlsHandshake *handshake.Handshake) error {
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

	return nil
}

type closeContext struct {
	context.Context //nolint:containedctx
	done            chan struct{}
	errMu           sync.RWMutex
	err             error
	doneOnce        sync.Once
}

func (c *closeContext) Done() <-chan struct{} {
	return c.done
}

func (c *closeContext) Err() error {
	c.errMu.RLock()
	err := c.err
	c.errMu.RUnlock()
	if err != nil {
		return err
	}

	return c.Context.Err()
}

func (c *closeContext) close(err error) {
	c.doneOnce.Do(func() {
		c.errMu.Lock()
		c.err = err
		c.errMu.Unlock()
		close(c.done)
	})
}

func (c *Conn) contextWithClose(ctx context.Context) (context.Context, context.CancelFunc) {
	closeCtx := &closeContext{
		Context: ctx,
		done:    make(chan struct{}),
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-c.closed.Done():
			closeCtx.close(context.Canceled)
		case <-ctx.Done():
			err := ctx.Err()
			if err == nil {
				err = context.DeadlineExceeded
			}
			closeCtx.close(err)
		case <-stop:
		}
	}()

	var stopOnce sync.Once
	cancel := func() {
		stopOnce.Do(func() {
			close(stop)
		})
	}

	return closeCtx, cancel
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
	seq, err := c.nextLocalSequenceNumber(epoch)
	if err != nil {
		return nil, err
	}
	pkt.Record.Header.SequenceNumber = seq

	if c.state.LocalVersion.Equal(protocol.Version1_3) && pkt.ShouldEncrypt {
		return c.processProtectedPacket(pkt, seq)
	}

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

func (c *Conn) nextLocalSequenceNumber(epoch uint16) (uint64, error) {
	for len(c.state.LocalSequenceNumber) <= int(epoch) {
		c.state.LocalSequenceNumber = append(c.state.LocalSequenceNumber, uint64(0))
	}
	seq := atomic.AddUint64(&c.state.LocalSequenceNumber[epoch], 1) - 1
	if seq > recordlayer.MaxSequenceNumber {
		// RFC 6347 Section 4.1.0
		// The implementation must either abandon an association or rehandshake
		// prior to allowing the sequence number to wrap.
		return 0, dtlserrors.ErrSequenceNumberOverflow
	}

	return seq, nil
}

// processProtectedPacket writes a DTLS 1.3 protected record. The helpers below
// keep the AEAD plaintext at the DTLSInnerPlaintext content level: handshake
// header plus body for handshake records, and alert bytes for alert records.
// They intentionally do not pass a marshaled record-layer header as plaintext;
// application data, ACK, and CID protected writes are left for their own
// integrations.
func (c *Conn) processProtectedPacket(pkt *dtlsflight.Packet, seq uint64) ([]byte, error) {
	if pkt.ShouldWrapCID {
		return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	epoch := pkt.Record.Header.Epoch
	contentType, plaintext, err := marshalRecordContent(pkt.Record.Content)
	if err != nil {
		return nil, err
	}

	return c.sealRecordContent(epoch, seq, contentType, plaintext)
}

func marshalRecordContent(content protocol.Content) (protocol.ContentType, []byte, error) {
	switch content.(type) {
	case *handshake.Handshake, *alert.Alert:
	default:
		return 0, nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	plaintext, err := content.Marshal()
	if err != nil {
		return 0, nil, err
	}

	return content.ContentType(), plaintext, nil
}

func (c *Conn) sealRecordContent(
	epoch uint16,
	seq uint64,
	contentType protocol.ContentType,
	plaintext []byte,
) ([]byte, error) {
	tls13CipherSuite, ok := c.state.CipherSuite.(ciphersuite.CipherSuiteTLS13)
	if !ok || !tls13CipherSuite.IsInitialized() {
		return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	header := recordlayer.UnifiedHeader{
		EpochLow:       uint8(epoch & 0x3),
		SequenceNumber: uint16(seq & 0xffff), //nolint:gosec // G115
		SeqBit:         true,
		LengthBit:      true,
	}

	ciphertext, err := tls13CipherSuite.Seal(
		header,
		seq,
		contentType,
		plaintext,
	)
	if err != nil {
		return nil, err
	}

	return ciphertext.Marshal()
}

//nolint:cyclop
func (c *Conn) processHandshakePacket(pkt *dtlsflight.Packet, dtlsHandshake *handshake.Handshake) ([][]byte, error) {
	if c.state.LocalVersion.Equal(protocol.Version1_3) && pkt.ShouldEncrypt {
		return c.processProtectedHandshakePacket(pkt, dtlsHandshake)
	}

	rawPackets := make([][]byte, 0)

	handshakeFragments, err := c.fragmentHandshake(dtlsHandshake)
	if err != nil {
		return nil, err
	}
	epoch := pkt.Record.Header.Epoch

	for _, handshakeFragment := range handshakeFragments {
		seq, err := c.nextLocalSequenceNumber(epoch)
		if err != nil {
			return nil, err
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

func (c *Conn) processProtectedHandshakePacket(
	pkt *dtlsflight.Packet,
	dtlsHandshake *handshake.Handshake,
) ([][]byte, error) {
	if pkt == nil || pkt.Record == nil || dtlsHandshake == nil {
		// todo:  this is a temporary error until we handle this in a better way.
		// nolint:godox
		return nil, dtlserrors.ErrInvalidPacket
	}
	if pkt.ShouldWrapCID {
		return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	handshakeFragments, err := c.fragmentHandshake(dtlsHandshake)
	if err != nil {
		return nil, err
	}

	rawPackets := make([][]byte, 0, len(handshakeFragments))
	epoch := pkt.Record.Header.Epoch
	for _, handshakeFragment := range handshakeFragments {
		seq, err := c.nextLocalSequenceNumber(epoch)
		if err != nil {
			return nil, err
		}
		pkt.Record.Header.ContentType = protocol.ContentTypeHandshake
		pkt.Record.Header.ContentLen = uint16(len(handshakeFragment)) //nolint:gosec // G115
		pkt.Record.Header.SequenceNumber = seq

		rawPacket, err := c.sealRecordContent(
			epoch,
			seq,
			protocol.ContentTypeHandshake,
			handshakeFragment,
		)
		if err != nil {
			return nil, err
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

	pkts, err := c.unpackDatagram(b[:i])
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
		s := dtlshandshake.RecvHandshakeState{
			Done:         make(chan struct{}),
			IsRetransmit: isRetransmit,
		}
		select {
		case c.handshakeRecv <- s:
			// If the other party may retransmit the flight,
			// we should respond even if it not a new message.
			<-s.Done
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

func (c *Conn) maxQueueableFutureEpoch(remoteEpoch uint16) uint16 {
	maxEpoch := remoteEpoch + 1
	if remoteEpoch >= dtlsflight13.EpochHandshake {
		return maxEpoch
	}
	if c.state.LocalVersion.Equal(protocol.Version1_3) {
		return dtlsflight13.EpochHandshake
	}
	if !c.state.LocalVersion.Equal(protocol.Version{}) {
		return maxEpoch
	}
	if c.handshakeConfig != nil && c.handshakeConfig.MaxVersion.Equal(protocol.Version1_3) {
		return dtlsflight13.EpochHandshake
	}

	return maxEpoch
}

func (c *Conn) unpackDatagram(buf []byte) ([][]byte, error) {
	if len(buf) == 0 {
		return nil, nil
	}
	if c.state.LocalVersion.Equal(protocol.Version1_3) ||
		protocol.IsDTLS13Ciphertext(protocol.ContentType(buf[0])) {
		return recordlayer.UnpackDatagram13(buf, 0, true)
	}

	return recordlayer.ContentAwareUnpackDatagram(buf, len(c.state.GetLocalConnectionID()))
}

func (c *Conn) queueableCiphertextEpoch(epochLow uint8, remoteEpoch uint16) bool {
	for epoch := remoteEpoch + 1; epoch <= c.maxQueueableFutureEpoch(remoteEpoch); epoch++ {
		if uint8(epoch&recordlayer.TwoLowBitsMask) == epochLow {
			return true
		}
	}

	return false
}

func (c *Conn) unmarshalCiphertextRecord(buf []byte) (recordlayer.CiphertextRecord13, error) {
	record := recordlayer.CiphertextRecord13{}
	hasCID := buf[0]&recordlayer.UnifiedHeaderCIDBit != 0
	localCID := c.state.GetLocalConnectionID()
	if hasCID {
		if len(localCID) == 0 {
			return record, dtlserrors.ErrInvalidCiphertextHeader
		}
		record.Header.ConnectionID = make([]byte, len(localCID))
	}

	if err := record.Unmarshal(buf); err != nil {
		return record, err
	}
	if len(localCID) > 0 && !hasCID {
		return record, dtlserrors.ErrInvalidCiphertextHeader
	}
	if hasCID {
		if !bytes.Equal(localCID, record.Header.ConnectionID) {
			return record, dtlserrors.ErrInvalidCiphertextHeader
		}

		return record, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	return record, nil
}

func (c *Conn) openCiphertextRecord(
	record recordlayer.CiphertextRecord13,
) (recordlayer.InnerPlaintext, uint64, error) {
	if len(record.Header.ConnectionID) > 0 {
		return recordlayer.InnerPlaintext{}, 0, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	remoteEpoch := c.state.GetRemoteEpoch()
	if record.Header.EpochLow != uint8(remoteEpoch&recordlayer.TwoLowBitsMask) {
		return recordlayer.InnerPlaintext{}, 0, dtlserrors.ErrInvalidEpoch
	}

	tls13CipherSuite, ok := c.state.CipherSuite.(ciphersuite.CipherSuiteTLS13)
	if !ok || !tls13CipherSuite.IsInitialized() {
		return recordlayer.InnerPlaintext{}, 0, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	clearHeader, err := tls13CipherSuite.UnmaskSequenceNumber(record.Header, record.EncryptedRecord)
	if err != nil {
		return recordlayer.InnerPlaintext{}, 0, err
	}

	sequenceNumber := reconstructSequenceNumber(
		clearHeader.SequenceNumber,
		clearHeader.SeqBit,
		c.highestRemoteSequenceNumber(remoteEpoch),
	)
	innerPlaintext, err := tls13CipherSuite.Open(record.Header, sequenceNumber, record.EncryptedRecord)
	if err != nil {
		return recordlayer.InnerPlaintext{}, 0, err
	}

	switch innerPlaintext.RealType {
	case protocol.ContentTypeAlert,
		protocol.ContentTypeHandshake,
		protocol.ContentTypeApplicationData,
		protocol.ContentTypeACK:
	default:
		return recordlayer.InnerPlaintext{}, 0, dtlserrors.ErrInvalidContentType
	}

	return innerPlaintext, sequenceNumber, nil
}

func reconstructSequenceNumber(partial uint16, seqBit bool, highest uint64) uint64 {
	bits := uint(8)
	if seqBit {
		bits = 16
	}

	window := uint64(1) << bits
	halfWindow := window / 2
	mask := window - 1
	expected := highest + 1
	candidate := (expected & ^mask) | (uint64(partial) & mask)
	if candidate+halfWindow <= expected {
		return candidate + window
	}
	if candidate > expected+halfWindow && candidate >= window {
		return candidate - window
	}

	return candidate
}

func (c *Conn) highestRemoteSequenceNumber(epoch uint16) uint64 {
	if int(epoch) >= len(c.state.RemoteSequenceNumber) {
		return 0
	}

	return atomic.LoadUint64(&c.state.RemoteSequenceNumber[epoch])
}

func (c *Conn) updateRemoteSequenceNumber(epoch uint16, sequenceNumber uint64) {
	for len(c.state.RemoteSequenceNumber) <= int(epoch) {
		c.state.RemoteSequenceNumber = append(c.state.RemoteSequenceNumber, 0)
	}
	for {
		highest := atomic.LoadUint64(&c.state.RemoteSequenceNumber[epoch])
		if sequenceNumber <= highest {
			return
		}
		if atomic.CompareAndSwapUint64(&c.state.RemoteSequenceNumber[epoch], highest, sequenceNumber) {
			return
		}
	}
}

func marshalInnerPlaintextRecord(
	epoch uint16,
	sequenceNumber uint64,
	innerPlaintext recordlayer.InnerPlaintext,
) ([]byte, *recordlayer.Header, error) {
	header := &recordlayer.Header{
		ContentType:    innerPlaintext.RealType,
		ContentLen:     uint16(len(innerPlaintext.Content)), //nolint:gosec // G115
		Version:        protocol.Version1_2,
		Epoch:          epoch,
		SequenceNumber: sequenceNumber,
	}
	rawHeader, err := header.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return append(rawHeader, innerPlaintext.Content...), header, nil
}

func (c *Conn) prepareIncomingPacket(
	buf []byte,
	rAddr net.Addr,
	enqueue bool,
) (incomingPacketState, bool) {
	if protocol.IsDTLS13Ciphertext(protocol.ContentType(buf[0])) {
		return c.prepareCiphertextPacket(buf, rAddr, enqueue)
	}

	return c.prepareLegacyPacket(buf, rAddr, enqueue)
}

func (c *Conn) prepareCiphertextPacket(
	buf []byte,
	rAddr net.Addr,
	enqueue bool,
) (incomingPacketState, bool) {
	ciphertext, err := c.unmarshalCiphertextRecord(buf)
	if err != nil {
		c.log.Debugf("discarded broken ciphertext packet: %v", err)

		return incomingPacketState{}, false
	}

	remoteEpoch := c.state.GetRemoteEpoch()
	if ciphertext.Header.EpochLow != uint8(remoteEpoch&recordlayer.TwoLowBitsMask) {
		c.handleFutureCiphertextPacket(ciphertext.Header.EpochLow, remoteEpoch, rAddr, buf, enqueue)

		return incomingPacketState{}, false
	}

	if c.queueIfCipherSuiteUninitialized(rAddr, buf, enqueue, "handshake not finished, queuing ciphertext packet") {
		return incomingPacketState{}, false
	}

	innerPlaintext, sequenceNumber, err := c.openCiphertextRecord(ciphertext)
	if err != nil {
		c.log.Debugf("%s: decrypt failed: %s", srvCliStr(c.state.IsClient), err)

		return incomingPacketState{}, false
	}

	markPacketAsValid, ok := c.protectedReplayMarker(remoteEpoch, sequenceNumber)
	if !ok {
		return incomingPacketState{}, false
	}

	return c.prepareInnerPlaintextRecord(remoteEpoch, sequenceNumber, innerPlaintext, markPacketAsValid)
}

func (c *Conn) prepareInnerPlaintextRecord(
	remoteEpoch uint16,
	sequenceNumber uint64,
	innerPlaintext recordlayer.InnerPlaintext,
	markPacketAsValid func() bool,
) (incomingPacketState, bool) {
	switch innerPlaintext.RealType {
	case protocol.ContentTypeHandshake, protocol.ContentTypeAlert:
		plaintext, header, err := marshalInnerPlaintextRecord(remoteEpoch, sequenceNumber, innerPlaintext)
		if err != nil {
			c.log.Debugf("converting ciphertext record to inner plaintext failed: %s", err)

			return incomingPacketState{}, false
		}

		return incomingPacketState{
			buf:               plaintext,
			header:            header,
			markPacketAsValid: markPacketAsValid,
		}, true
	case protocol.ContentTypeACK, protocol.ContentTypeApplicationData:
		_ = markPacketAsValid()

		return incomingPacketState{}, false
	default:
		c.log.Debugf("discarded ciphertext packet with invalid inner type: %d", innerPlaintext.RealType)

		return incomingPacketState{}, false
	}
}

func (c *Conn) handleFutureCiphertextPacket(
	epochLow uint8,
	remoteEpoch uint16,
	rAddr net.Addr,
	buf []byte,
	enqueue bool,
) {
	if !c.queueableCiphertextEpoch(epochLow, remoteEpoch) {
		c.log.Debugf("discarded future ciphertext packet (epoch low: %d)", epochLow)

		return
	}
	if enqueue {
		if ok := c.enqueueEncryptedPackets(addrPkt{rAddr, buf}); ok {
			c.log.Debug("received ciphertext packet of next epoch, queuing packet")
		}
	}
}

func (c *Conn) protectedReplayMarker(epoch uint16, sequenceNumber uint64) (func() bool, bool) {
	for len(c.state.ReplayDetector) <= int(epoch) {
		c.state.ReplayDetector = append(c.state.ReplayDetector,
			replaydetector.New(c.replayProtectionWindow, ^uint64(0)),
		)
	}
	accept, ok := c.state.ReplayDetector[int(epoch)].Check(sequenceNumber)
	if !ok {
		c.log.Debugf("discarded duplicated packet (epoch: %d, seq: %d)", epoch, sequenceNumber)

		return nil, false
	}

	return func() bool {
		latest := accept()
		if latest {
			c.updateRemoteSequenceNumber(epoch, sequenceNumber)
		}

		return latest
	}, true
}

func (c *Conn) queueIfCipherSuiteUninitialized(
	rAddr net.Addr,
	buf []byte,
	enqueue bool,
	message string,
) bool {
	if c.state.CipherSuite != nil && c.state.CipherSuite.IsInitialized() {
		return false
	}
	if enqueue {
		if ok := c.enqueueEncryptedPackets(addrPkt{rAddr, buf}); ok {
			c.log.Debug(message)
		}
	}

	return true
}

func (c *Conn) prepareLegacyPacket(
	buf []byte,
	rAddr net.Addr,
	enqueue bool,
) (incomingPacketState, bool) {
	header, ok := c.unmarshalLegacyHeader(buf)
	if !ok {
		return incomingPacketState{}, false
	}
	if c.handleFutureLegacyPacket(header, rAddr, buf, enqueue) {
		return incomingPacketState{}, false
	}

	markPacketAsValid, ok := c.legacyReplayMarker(header)
	if !ok {
		return incomingPacketState{}, false
	}

	originalCID := false
	if header.Epoch != 0 {
		var decryptOK bool
		buf, originalCID, decryptOK = c.decryptLegacyPacket(header, buf, rAddr, enqueue)
		if !decryptOK {
			return incomingPacketState{}, false
		}
	}

	return incomingPacketState{
		buf:               buf,
		header:            header,
		markPacketAsValid: markPacketAsValid,
		originalCID:       originalCID,
	}, true
}

func (c *Conn) unmarshalLegacyHeader(buf []byte) (*recordlayer.Header, bool) {
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

		return nil, false
	}

	return header, true
}

func (c *Conn) handleFutureLegacyPacket(
	header *recordlayer.Header,
	rAddr net.Addr,
	buf []byte,
	enqueue bool,
) bool {
	remoteEpoch := c.state.GetRemoteEpoch()
	if header.Epoch <= remoteEpoch {
		return false
	}
	if header.Epoch > c.maxQueueableFutureEpoch(remoteEpoch) {
		c.log.Debugf("discarded future packet (epoch: %d, seq: %d)",
			header.Epoch, header.SequenceNumber,
		)

		return true
	}
	if enqueue {
		if ok := c.enqueueEncryptedPackets(addrPkt{rAddr, buf}); ok {
			c.log.Debug("received packet of next epoch, queuing packet")
		}
	}

	return true
}

func (c *Conn) legacyReplayMarker(header *recordlayer.Header) (func() bool, bool) {
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

		return nil, false
	}

	return markPacketAsValid, true
}

func (c *Conn) decryptLegacyPacket(
	header *recordlayer.Header,
	buf []byte,
	rAddr net.Addr,
	enqueue bool,
) ([]byte, bool, bool) {
	if c.queueIfCipherSuiteUninitialized(rAddr, buf, enqueue, "handshake not finished, queuing packet") {
		return nil, false, false
	}

	if !c.validateLegacyCIDPresence(header) {
		return nil, false, false
	}

	decrypted, ok := c.decryptLegacyRecord(header, buf)
	if !ok {
		return nil, false, false
	}

	if header.ContentType == protocol.ContentTypeConnectionID {
		decrypted, ok = c.unpackLegacyCIDPacket(header, decrypted)
		if !ok {
			return nil, false, false
		}

		return decrypted, true, c.validateLegacyCID(header)
	}

	return decrypted, false, c.validateLegacyCID(header)
}

func (c *Conn) validateLegacyCIDPresence(header *recordlayer.Header) bool {
	if len(c.state.GetLocalConnectionID()) == 0 || header.ContentType == protocol.ContentTypeConnectionID {
		return true
	}

	c.log.Debug("discarded packet missing connection ID after value negotiated")

	return false
}

func (c *Conn) decryptLegacyRecord(header *recordlayer.Header, buf []byte) ([]byte, bool) {
	var decryptHeader recordlayer.Header
	if header.ContentType == protocol.ContentTypeConnectionID {
		decryptHeader.ConnectionID = make([]byte, len(c.state.GetLocalConnectionID()))
	}
	decrypted, err := c.state.CipherSuite.Decrypt(decryptHeader, buf)
	if err != nil {
		c.log.Debugf("%s: decrypt failed: %s", srvCliStr(c.state.IsClient), err)

		return nil, false
	}

	return decrypted, true
}

func (c *Conn) validateLegacyCID(header *recordlayer.Header) bool {
	if bytes.Equal(c.state.GetLocalConnectionID(), header.ConnectionID) {
		return true
	}

	c.log.Debug("unexpected connection ID")

	return false
}

func (c *Conn) unpackLegacyCIDPacket(header *recordlayer.Header, buf []byte) ([]byte, bool) {
	ip := &recordlayer.InnerPlaintext{}
	if err := ip.Unmarshal(buf[header.Size():]); err != nil { //nolint:govet
		c.log.Debugf("unpacking inner plaintext failed: %s", err)

		return nil, false
	}
	unpacked := &recordlayer.Header{
		ContentType:    ip.RealType,
		ContentLen:     uint16(len(ip.Content)), //nolint:gosec // G115
		Version:        header.Version,
		Epoch:          header.Epoch,
		SequenceNumber: header.SequenceNumber,
	}
	rawHeader, err := unpacked.Marshal()
	if err != nil {
		c.log.Debugf("converting CID record to inner plaintext failed: %s", err)

		return nil, false
	}

	return append(rawHeader, ip.Content...), true
}

//nolint:gocognit,gocyclo,cyclop,maintidx
func (c *Conn) handleIncomingPacket(
	ctx context.Context,
	buf []byte,
	rAddr net.Addr,
	enqueue bool,
) (bool, bool, *alert.Alert, error) {
	if len(buf) == 0 {
		return false, false, nil, nil
	}

	prepared, ok := c.prepareIncomingPacket(buf, rAddr, enqueue)
	if !ok {
		return false, false, nil, nil
	}
	buf = prepared.buf
	header := prepared.header
	markPacketAsValid := prepared.markPacketAsValid

	c.syncFragmentBufferHandshakeSequence()
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
	if prepared.originalCID && isLatestSeqNum {
		if rAddr != c.RemoteAddr() {
			c.lock.Lock()
			c.rAddr = rAddr
			c.lock.Unlock()
		}
	}

	return false, false, nil, nil
}

func (c *Conn) syncFragmentBufferHandshakeSequence() {
	if c.fragmentBuffer == nil || c.state.HandshakeRecvSequence <= 0 ||
		c.state.HandshakeRecvSequence > int(^uint16(0)) {
		return
	}

	c.fragmentBuffer.advanceTo(uint16(c.state.HandshakeRecvSequence)) //nolint:gosec // G115 checked above.
}

func (c *Conn) recvHandshake() <-chan dtlshandshake.RecvHandshakeState {
	return c.handshakeRecv
}

func (c *Conn) notify(ctx context.Context, level alert.Level, desc alert.Description) error {
	if level == alert.Fatal && len(c.state.SessionID) > 0 { //nolint:nestif
		if c.state.LocalVersion == protocol.Version1_2 {
			// According to the RFC, we need to delete the stored session.
			// https://datatracker.ietf.org/doc/html/rfc5246#section-7.2
			if c.handshakeConfig.HasSessionStore {
				c.log.Tracef("clean invalid session: %s", c.state.SessionID)
				if err := c.handshakeConfig.DelSession(c.sessionKey()); err != nil {
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
func (c *Conn) negotiateVersionClient(ctx context.Context) ([]*dtlsflight.Packet, error) {
	gen, _, ok := dtlsflight13.GetGenerator(dtlsflight13.Flight1)
	if !ok {
		return nil, dtlserrors.ErrFlightUnimplemented13
	}
	pkts, dtlsAlert, err := gen(adaptFlightConn(c), &c.state, c.handshakeCache, c.handshakeConfig)
	if dtlsAlert != nil {
		if alertErr := c.notify(ctx, dtlsAlert.Level, dtlsAlert.Description); alertErr != nil && err == nil {
			err = alertErr
		}
	}
	if err != nil {
		return nil, err
	}

	c.stampHandshakeSequence(pkts)
	if err := dtlshandshake.ValidateClientHelloInitialFlights(pkts); err != nil {
		return nil, err
	}
	if err := c.writePackets(ctx, pkts); err != nil {
		return nil, err
	}

	for {
		if err := c.readAndBufferNoFSM(ctx); err != nil {
			return nil, err
		}
		if ok, err := c.pickVersionFromServerResponse(); err != nil {
			return nil, err
		} else if ok {
			return pkts, nil
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
	s := dtlshandshake.RecvHandshakeState{
		Done:         make(chan struct{}),
		IsRetransmit: false,
	}
	select {
	case c.handshakeRecv <- s:
		select {
		case <-s.Done:
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

	pkts, err := c.unpackDatagram(b[:i])
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
		fsm, err := dtlshandshake.NewFSM13(
			&c.state,
			c.handshakeCache,
			c.handshakeConfig,
			start.flight13,
			start.flights,
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
		c.fsm = dtlshandshake.NewFSM12(&c.state, c.handshakeCache, c.handshakeConfig, start.flight12, start.flights)
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
		err := c.fsm.Run(ctxHs, handshakeConnAdapter{c}, start.fsmState)
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
	closedByUser := c.connectionClosedByUser
	if byUser {
		c.connectionClosedByUser = true
	}
	isClosed := c.isConnectionClosed()
	if !isClosed {
		c.closed.Close()
	}
	c.closeLock.Unlock()

	cancelHandshaker()
	cancelHandshakeReader()

	if closedByUser || isClosed {
		return nil
	}

	if c.isHandshakeCompletedSuccessfully() && byUser {
		// Discard error from notify() to return non-error on user Close()
		// even if the underlying connection is already closed.
		_ = c.notify(context.Background(), alert.Warning, alert.CloseNotify)
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
		return []byte(c.rAddr.String() + "_" + c.handshakeConfig.ServerName)
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
