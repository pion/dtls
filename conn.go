// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package dtls implements Datagram Transport Layer Security (DTLS) 1.2 and 1.3.
package dtls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	dtlsciphersuite "github.com/pion/dtls/v4/internal/ciphersuite"
	"github.com/pion/dtls/v4/internal/closer"
	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	dtlsflight12 "github.com/pion/dtls/v4/internal/flight/flight12"
	dtlsflight13 "github.com/pion/dtls/v4/internal/flight/flight13"
	dtlsfragmentbuffer "github.com/pion/dtls/v4/internal/fragmentbuffer"
	dtlshandshake "github.com/pion/dtls/v4/internal/handshake"
	"github.com/pion/dtls/v4/internal/negotiation"
	idtlsnet "github.com/pion/dtls/v4/internal/net"
	"github.com/pion/dtls/v4/internal/net/udp"
	"github.com/pion/dtls/v4/internal/recordwire"
	dtlsrrc "github.com/pion/dtls/v4/internal/rrc"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/internal/util"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/pion/transport/v5/deadline"
	"github.com/pion/transport/v5/netctx"
	"github.com/pion/transport/v5/replaydetector"
)

const (
	// defaultReceiveBufferSize is the default size of the buffers used to
	// receive datagrams. Overridable via WithReceiveBufferSize.
	defaultReceiveBufferSize = 8192
	// Default replay protection window is specified by RFC 6347 Section 4.1.2.6.
	defaultReplayProtectionWindow = 64
	maxPlaintextRecordLen         = 1 << 14
	maxCIDInnerPlaintextLen       = maxPlaintextRecordLen
	maxDTLS13InnerPlaintextLen    = maxPlaintextRecordLen + 1
	// maxAppDataPacketQueueSize is the maximum number of app data packets we will.
	// enqueue before the handshake is completed.
	maxAppDataPacketQueueSize = 100
)

var (
	errRecordAuthentication = errors.New("record authentication failed")
	errRecordOperational    = errors.New("record protection operational failure")
)

func operationalProtectionError(err error) error {
	return fmt.Errorf("%w: %w", errRecordOperational, err)
}

func invalidKeyingLabels() map[string]bool {
	return map[string]bool{
		"client finished": true,
		"server finished": true,
		"master secret":   true,
		"key expansion":   true,
	}
}

type addrPkt struct {
	rAddr               net.Addr
	data                []byte
	datagramContainsCID bool
	pendingCID          bool
}

type injectedPkt struct {
	addrPkt
	done chan struct{}
}

// readBufferLease owns a recyclable read buffer for one datagram-processing
// call. Anything retained beyond that call must take an exact owned copy.
type readBufferLease struct {
	conn                 *Conn
	pool                 *sync.Pool
	recyclableReadBuffer *[]byte
	datagramContainsCID  bool
	pendingCID           bool
}

func (w *readBufferLease) enqueue(packet addrPkt) bool {
	packet.datagramContainsCID = w.datagramContainsCID
	packet.pendingCID = w.pendingCID && protocol.IsDTLS13Ciphertext(protocol.ContentType(packet.data[0]))

	return w.conn.enqueueEncryptedPackets(packet)
}

func (w *readBufferLease) releaseReadBuffer() {
	readBuffer := w.recyclableReadBuffer
	w.recyclableReadBuffer = nil
	if readBuffer != nil && w.pool != nil {
		w.pool.Put(readBuffer)
	}
}

type incomingPacketState struct {
	raw               []byte
	content           []byte
	contentType       protocol.ContentType
	number            protocol.RecordNumber
	markPacketAsValid func() bool
	originalCID       bool
}

type packetOutcome struct {
	containsHandshake bool
	retransmit        bool
	receivedACK       *protocol.ACK
	responseAlert     *alert.Alert
}

type datagramProcessingSummary struct {
	containsHandshake bool
	retransmit        bool
	receivedACKs      []protocol.ACK
}

type readLoopErrorAction uint8

const (
	readLoopStop readLoopErrorAction = iota
	readLoopContinue
	readLoopDeliverAndContinue
	readLoopCloseAndStop
)

type handshakeStart struct {
	flight12  dtlsflight12.Flight
	flight13  dtlsflight13.Flight
	fsmState  dtlshandshake.State
	flights   []*dtlsflight.Outbound
	postSetup func(context.Context)
}

type handshakeConn struct {
	conn *Conn
}

func (c handshakeConn) Notify(ctx context.Context, level alert.Level, desc alert.Description) error {
	return c.conn.notify(ctx, level, desc)
}

func (c handshakeConn) WritePackets(ctx context.Context, pkts []*dtlsflight.Outbound) (*dtlshandshake.WriteResult, error) {
	return c.conn.writePacketsWithResult(ctx, pkts, true)
}

func (c handshakeConn) RecvHandshake() <-chan dtlshandshake.RecvHandshakeState {
	return c.conn.recvHandshake()
}

func (c handshakeConn) SetLocalEpoch(epoch uint64) {
	c.conn.setLocalEpoch(epoch)
}

func (c handshakeConn) CommitLocalKeyUpdate(generation *dtlsstate.TrafficGeneration) error {
	return c.conn.commitLocalKeyUpdate(generation)
}

func (c handshakeConn) TakePendingACKs() []protocol.RecordNumber {
	return c.conn.takePendingACKs()
}

func (c handshakeConn) HandleQueuedPackets(ctx context.Context) error {
	return c.conn.handleQueuedPackets(ctx)
}

func (c handshakeConn) SessionKey() []byte {
	return c.conn.sessionKey()
}

func adaptFlightConn(conn *Conn) dtlsflight.Conn {
	if conn == nil {
		return nil
	}

	return handshakeConn{conn}
}

func srvCliStr(isClient bool) string {
	if isClient {
		return "client"
	}

	return "server"
}

// Conn represents a DTLS connection.
type Conn struct {
	lock           sync.RWMutex                       // Internal lock (must not be public)
	nextConn       netctx.PacketConn                  // Embedded Conn, typically a udpconn we read/write from
	packetConn     *udp.PacketConn                    // Listener CID and address routing.
	fragmentBuffer *dtlsfragmentbuffer.FragmentBuffer // out-of-order and missing fragment handling
	handshakeCache *dtlsflight.Cache                  // caching of handshake messages for verifyData generation
	pendingACKs    []protocol.RecordNumber
	pendingCIDACKs map[protocol.RecordNumber]uint16
	decrypted      chan any // Decrypted Application Data or error, pull by calling `Read`
	rAddr          net.Addr
	state          dtlsstate.Active // active DTLS version state

	maximumTransmissionUnit int
	paddingLengthGenerator  func(uint) uint
	readBufferPool          *sync.Pool

	handshakeEstablished *dtlshandshake.Establishment
	handshakeMutex       sync.Mutex
	handshakeDone        chan struct{}
	writeLock            sync.Mutex

	encryptedPackets []addrPkt

	connectionClosedByUser bool
	closeLock              sync.Mutex
	closed                 *closer.Closer

	readDeadline  *deadline.Deadline
	writeDeadline *deadline.Deadline

	log logging.LeveledLogger

	reading             chan struct{}
	handshakeRecv       chan dtlshandshake.RecvHandshakeState
	detached            *DetachedConn
	inboundPacketInject chan injectedPkt
	// injectDone is set by the read loop and closed by the handshake goroutine.
	injectMu              sync.Mutex
	injectDone            chan struct{}
	pendingRead           chan readResult
	cancelHandshaker      func()
	cancelHandshakeReader func()

	fsm dtlshandshake.FSM

	replayProtectionWindow uint

	// Allows intercepting and rerouting outgoing handshake packets.
	outboundHandshakePacketInterceptor func(datagrams [][]byte, rAddr net.Addr) bool
	// Allows getting notified about incoming handshake packets.
	inboundHandshakePacketNotifier func(packet []byte)

	handshakeConfig *dtlsconfig.HandshakeConfig

	cidPathMigrationPolicy cidPathMigrationPolicy
	registeredLocalCID     []byte
	registeredReceiveCIDs  *dtlsstate.CIDReceiveSet
	rrc                    dtlsrrc.Manager
}

// createConn creates a new DTLS connection.
// Caller is responsible for validating the config before calling this function.
func createConn(nextConn net.PacketConn, rAddr net.Addr, config *dtlsConfig, isClient bool, resumeState *dtlsstate.State) (*Conn, error) {
	if nextConn == nil {
		return nil, dtlserrors.ErrNilNextConn
	}

	configValues, err := newConnConfigValues(config)
	if err != nil {
		return nil, err
	}

	handshakeConfig := newHandshakeConfig(config, configValues, resumeState)
	conn := newConn(nextConn, rAddr, configValues, handshakeConfig, isClient)
	conn.outboundHandshakePacketInterceptor = config.OutboundHandshakePacketInterceptor
	conn.inboundHandshakePacketNotifier = config.InboundHandshakePacketNotifier

	conn.setRemoteEpoch(0)
	conn.setLocalEpoch(0)

	return conn, nil
}

func newConn(nextConn net.PacketConn, rAddr net.Addr, configValues connConfigValues, handshakeConfig *dtlsconfig.HandshakeConfig, isClient bool) *Conn {
	conn := &Conn{
		rAddr:                   rAddr,
		handshakeConfig:         handshakeConfig,
		fragmentBuffer:          dtlsfragmentbuffer.New(),
		handshakeCache:          dtlsflight.NewCache(),
		maximumTransmissionUnit: configValues.maximumTransmissionUnit,
		paddingLengthGenerator:  configValues.paddingLengthGenerator,
		cidPathMigrationPolicy:  configValues.cidPathMigrationPolicy,
		readBufferPool:          readBufferPoolForSize(configValues.receiveBufferSize),

		decrypted: make(chan any, 1),
		log:       configValues.logger,

		readDeadline:  deadline.New(),
		writeDeadline: deadline.New(),

		reading:               make(chan struct{}, 1),
		handshakeRecv:         make(chan dtlshandshake.RecvHandshakeState),
		inboundPacketInject:   make(chan injectedPkt),
		handshakeEstablished:  dtlshandshake.NewEstablishment(),
		closed:                closer.NewCloser(),
		cancelHandshaker:      func() {},
		cancelHandshakeReader: func() {},

		replayProtectionWindow: uint(configValues.replayProtectionWindow), //nolint:gosec // G115

		state: dtlsstate.NewActive(isClient),
	}
	if nextConn != nil {
		conn.nextConn = netctx.NewPacketConn(nextConn)
		conn.packetConn, _ = nextConn.(*udp.PacketConn)
	}

	return conn
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
//
//nolint:cyclop
func (c *Conn) HandshakeContext(ctx context.Context) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.isHandshakeCompletedSuccessfully() {
		return nil
	}

	handshakeDone := make(chan struct{})
	defer close(handshakeDone)
	defer c.finishInject() // the FSM stops asking for datagrams once it is done

	c.closeLock.Lock()
	c.handshakeDone = handshakeDone
	c.closeLock.Unlock()

	// rfc5246#section-7.4.3
	// In addition, the hash and signature algorithms MUST be compatible
	// with the key in the server's end-entity certificate.
	common := dtlsstate.CommonState(c.state)
	if !common.IsClient {
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

	common = dtlsstate.CommonState(c.state)
	c.handshakeConfig.LocalCipherSuites = filterCipherSuitesForVersion(c.handshakeConfig.LocalCipherSuites, common.LocalVersion)
	if len(c.handshakeConfig.LocalCipherSuites) == 0 {
		return dtlserrors.ErrNoAvailableCipherSuites
	}

	if err := c.handshake(ctx, start); err != nil {
		if !c.isHandshakeCompletedSuccessfully() {
			common.SetSRTPProtectionProfile(0)
		}

		return err
	}

	if common.LocalVersion == protocol.Version1_3 {
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
		start := c.prepareHandshakeStart12()
		c.lock.Lock()
		defer c.lock.Unlock()

		return start, c.registerLocalCID()
	}
	if c.handshakeConfig.MinVersion == protocol.Version1_3 {
		return c.prepareHandshakeStart13(), nil
	}
	if dtlsstate.CommonState(c.state).IsClient {
		return c.prepareDualStackClientHandshakeStart(ctx)
	}

	return c.prepareDualStackServerHandshakeStart(ctx)
}

func (c *Conn) prepareHandshakeStart12() handshakeStart {
	isClient := dtlsstate.CommonState(c.state).IsClient
	if c.handshakeConfig.ResumeState != nil {
		c.state = c.handshakeConfig.ResumeState
		dtlsstate.CommonState(c.state).LocalVersion = protocol.Version1_2

		if isClient {
			return handshakeStart{flight12: dtlsflight12.Flight5, fsmState: dtlshandshake.StateFinished}
		}

		return handshakeStart{flight12: dtlsflight12.Flight6, fsmState: dtlshandshake.StateFinished}
	}

	state := dtlsstate.Activate12(c.state)
	c.state = state
	state.LocalVersion = protocol.Version1_2
	if isClient {
		return handshakeStart{flight12: dtlsflight12.Flight1, fsmState: dtlshandshake.StatePreparing}
	}

	return handshakeStart{flight12: dtlsflight12.Flight0, fsmState: dtlshandshake.StatePreparing}
}

func (c *Conn) prepareHandshakeStart13() handshakeStart {
	state := dtlsstate.Activate13(c.state)
	c.state = state
	state.LocalVersion = protocol.Version1_3
	if state.IsClient {
		return handshakeStart{flight13: dtlsflight13.Flight1, fsmState: dtlshandshake.StatePreparing}
	}

	return handshakeStart{flight13: dtlsflight13.Flight0, fsmState: dtlshandshake.StatePreparing}
}

func (c *Conn) prepareDualStackClientHandshakeStart(ctx context.Context) (handshakeStart, error) {
	initialFlights, err := c.negotiateVersionClient(ctx)
	if err != nil {
		return handshakeStart{}, err
	}

	return handshakeStart{flight12: dtlsflight12.Flight1, flight13: dtlsflight13.Flight1, fsmState: dtlshandshake.StateWaiting, flights: initialFlights, postSetup: func(ctx context.Context) { c.primeHandshakeRecv(ctx) }}, nil
}

func (c *Conn) prepareDualStackServerHandshakeStart(ctx context.Context) (handshakeStart, error) {
	err := c.negotiateVersionServer(ctx)
	if err != nil {
		return handshakeStart{}, err
	}

	return handshakeStart{
		flight12:  dtlsflight12.Flight0,
		flight13:  dtlsflight13.Flight0,
		fsmState:  dtlshandshake.StatePreparing,
		postSetup: func(ctx context.Context) { c.primeHandshakeRecv(ctx) },
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

// Dial connects to the given network address and establishes a DTLS connection on top.
func Dial(network string, rAddr *net.UDPAddr, opts ...ClientOption) (*Conn, error) {
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

// Client establishes a DTLS connection over an existing packet connection.
func Client(conn net.PacketConn, raddr net.Addr, opts ...ClientOption) (*Conn, error) {
	config, err := buildClientConfig(opts...)
	if err != nil {
		return nil, err
	}

	return clientWithConfig(conn, raddr, config)
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

// Server establishes a server-side DTLS connection over an existing packet connection.
func Server(conn net.PacketConn, raddr net.Addr, opts ...ServerOption) (*Conn, error) {
	config, err := buildServerConfig(opts...)
	if err != nil {
		return nil, err
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return serverWithConfig(conn, raddr, config)
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

	ctx, cancel := c.contextWithClose(c.writeDeadline.Context())
	defer cancel()

	err := c.writeApplicationData(ctx, []*dtlsflight.Outbound{
		c.newApplicationDataPacket(payload),
	})
	if errors.Is(err, context.Canceled) && errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		return 0, dtlserrors.ErrDeadlineExceeded
	}
	if err != nil {
		return 0, err
	}

	return len(payload), nil
}

func (c *Conn) newApplicationDataPacket(payload []byte) *dtlsflight.Outbound {
	return &dtlsflight.Outbound{
		Content: &protocol.ApplicationData{
			// The DTLS 1.3 FSM may retain this packet after Write returns on
			// cancellation, so take ownership before queueing it.
			Data: bytes.Clone(payload),
		},
		Protection: dtlsflight.ProtectionCiphertext,
	}
}

// KeyUpdateOptions controls a DTLS 1.3 application traffic-key update.
type KeyUpdateOptions struct {
	// RequestPeerUpdate asks the peer to update its sending keys in response.
	RequestPeerUpdate bool
}

// UpdateKeys requests a DTLS 1.3 application traffic-key update. It returns
// only after the peer acknowledges the KeyUpdate and the next local write
// generation has been committed.
func (c *Conn) UpdateKeys(ctx context.Context, options KeyUpdateOptions) error {
	updater, err := c.keyUpdateFSM(ctx)
	if err != nil {
		return err
	}
	request := handshake.KeyUpdateNotRequested
	if options.RequestPeerUpdate {
		request = handshake.KeyUpdateRequested
	}

	operationCtx, cancel := c.contextWithCloseAndWriteDeadline(ctx)
	defer cancel()

	return c.normalizeKeyUpdateError(ctx, operationCtx, updater.UpdateKeys(operationCtx, request))
}

func (c *Conn) keyUpdateFSM(ctx context.Context) (dtlshandshake.KeyUpdater, error) {
	if c.isConnectionClosed() {
		return nil, ErrConnClosed
	}
	select {
	case <-c.writeDeadline.Done():
		return nil, dtlserrors.ErrDeadlineExceeded
	default:
	}
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if dtlsstate.CommonState(c.state).LocalVersion != protocol.Version1_3 {
		return nil, dtlserrors.ErrUnsupportedProtocolVersion
	}

	updater, ok := c.fsm.(dtlshandshake.KeyUpdater)
	if !ok {
		return nil, dtlserrors.ErrNotImplemented
	}

	return updater, nil
}

func (c *Conn) normalizeKeyUpdateError(ctx, operationCtx context.Context, err error) error {
	if errors.Is(err, context.Canceled) {
		switch {
		case c.isConnectionClosed():
			return ErrConnClosed
		case errors.Is(context.Cause(operationCtx), context.DeadlineExceeded):
			return dtlserrors.ErrDeadlineExceeded
		case ctx.Err() != nil:
			return ctx.Err()
		}
	}

	return err
}

func (c *Conn) writeApplicationData(ctx context.Context, pkts []*dtlsflight.Outbound) error {
	if dtlsstate.CommonState(c.state).LocalVersion == protocol.Version1_3 {
		writer, ok := c.fsm.(dtlshandshake.ApplicationDataWriter)
		if !ok {
			return dtlserrors.ErrNotImplemented
		}

		return writer.WriteApplicationData(ctx, pkts)
	}

	epoch := dtlsstate.CommonState(c.state).LocalEpoch()
	for _, pkt := range pkts {
		pkt.Epoch = epoch
	}
	_, err := c.writePacketsWithResult(ctx, pkts, false)

	return err
}

// Close closes the connection.
func (c *Conn) Close() error {
	err := c.close(true)
	if c.detached != nil {
		c.detached.terminate(ErrConnClosed, false)
	}
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
	state, err := generateStateForVerifyConnection(c.state)
	if err != nil {
		return State{}, false
	}

	return *state, true
}

// SelectedSRTPProtectionProfile returns the selected SRTPProtectionProfile.
func (c *Conn) SelectedSRTPProtectionProfile() (SRTPProtectionProfile, bool) {
	profile := dtlsstate.CommonState(c.state).SRTPProtectionProfile()
	if profile == 0 {
		return 0, false
	}

	return profile, true
}

// RemoteSRTPMasterKeyIdentifier returns the MasterKeyIdentifier value from the use_srtp.
func (c *Conn) RemoteSRTPMasterKeyIdentifier() ([]byte, bool) {
	common := dtlsstate.CommonState(c.state)
	if profile := common.SRTPProtectionProfile(); profile == 0 {
		return nil, false
	}

	return bytes.Clone(common.RemoteSRTPMasterKeyIdentifier), true
}

func (c *Conn) writePackets(ctx context.Context, pkts []*dtlsflight.Outbound, handshake bool) error {
	_, err := c.writePacketsWithResult(ctx, pkts, handshake)

	return err
}

func (c *Conn) writePacketsWithResult(ctx context.Context, pkts []*dtlsflight.Outbound, handshake bool) (*dtlshandshake.WriteResult, error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	return c.writePacketsWithResultLocked(ctx, pkts, handshake)
}

func (c *Conn) writePacketsWithResultLocked(
	ctx context.Context,
	pkts []*dtlsflight.Outbound,
	handshake bool,
) (*dtlshandshake.WriteResult, error) {
	datagrams, rAddr, err := c.prepareRawPacketsTracked(pkts)
	if err != nil {
		return nil, err
	}

	result := &dtlshandshake.WriteResult{}
	if len(datagrams) == 0 {
		return result, nil
	}

	raw := make([][]byte, len(datagrams))
	for i := range datagrams {
		raw[i] = datagrams[i].raw
		result.TrackedRecords = append(result.TrackedRecords, datagrams[i].tracked...)
	}

	interceptor := c.outboundHandshakePacketInterceptor
	switch {
	case handshake && interceptor != nil && interceptor(raw, rAddr):
	case c.detached != nil:
		c.detached.publishDatagrams(raw, rAddr, handshake)
	default:
		if err = c.writeDatagrams(ctx, raw, rAddr); err != nil {
			return nil, err
		}
	}

	return result, nil
}

func (c *Conn) writeDatagrams(ctx context.Context, raw [][]byte, rAddr net.Addr) error {
	for _, datagram := range raw {
		if _, err := c.nextConn.WriteToContext(ctx, datagram, rAddr); err != nil {
			if errors.Is(err, context.Canceled) && c.isConnectionClosed() {
				return ErrConnClosed
			}

			return netError(err)
		}
	}

	return nil
}

type preparedDatagram struct {
	raw     []byte
	tracked []dtlshandshake.SentHandshakeRecord
}

func (c *Conn) prepareRawPacketsTracked(pkts []*dtlsflight.Outbound) ([]preparedDatagram, net.Addr, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	records, err := c.prepareRecordsTracked(pkts)
	if err != nil {
		return nil, nil, err
	}
	if len(records) == 0 {
		return nil, nil, nil
	}

	return c.compactPreparedRecords(records), c.rAddr, nil
}

func (c *Conn) prepareRecordsTracked(pkts []*dtlsflight.Outbound) ([]preparedRecord, error) {
	var records []preparedRecord
	for _, pkt := range pkts {
		prepared, err := c.prepareOutbound(pkt)
		if err != nil {
			return nil, err
		}
		records = append(records, prepared...)
	}

	return records, nil
}

func (c *Conn) prepareOutbound(outbound *dtlsflight.Outbound) ([]preparedRecord, error) {
	if outbound == nil || outbound.Content == nil || !validProtection(outbound.Protection) {
		return nil, dtlserrors.ErrInvalidPacket
	}
	if dtlsHandshake, ok := outbound.Content.(*handshake.Handshake); ok {
		if err := c.cacheHandshake(outbound, dtlsHandshake); err != nil {
			return nil, err
		}
		if err := c.registerLocalCID(); err != nil {
			return nil, err
		}

		return c.prepareHandshakeRecords(outbound, dtlsHandshake)
	}

	raw, err := c.prepareRecord(outbound)
	if err != nil {
		return nil, err
	}

	return []preparedRecord{{raw: raw}}, nil
}

func (c *Conn) cacheHandshake(outbound *dtlsflight.Outbound, dtlsHandshake *handshake.Handshake) error {
	handshakeRaw, err := dtlsHandshake.Marshal()
	if err != nil {
		return err
	}

	c.log.Tracef("[handshake:%v] -> %s (epoch: %d, seq: %d)", srvCliStr(dtlsstate.CommonState(c.state).IsClient), dtlsHandshake.Header.Type.String(), outbound.Epoch, dtlsHandshake.Header.MessageSequence)

	c.handshakeCache.Push(handshakeRaw, outbound.Epoch, dtlsHandshake.Header.MessageSequence, dtlsHandshake.Header.Type, dtlsstate.CommonState(c.state).IsClient)

	return nil
}

func (c *Conn) contextWithClose(ctx context.Context) (context.Context, context.CancelFunc) {
	closeCtx, cancel := context.WithCancelCause(ctx)

	detachLifetime := context.AfterFunc(c.closed, func() {
		err := c.closed.Err()
		if err == nil {
			err = context.Canceled
		}
		cancel(err)
	})

	detachDeadline := context.AfterFunc(c.writeDeadline.Context(), func() {
		err := c.writeDeadline.Err()
		if err == nil {
			err = context.DeadlineExceeded
		}
		cancel(err)
	})

	return closeCtx, func() {
		detachLifetime()
		detachDeadline()
		cancel(context.Canceled)
	}
}

func (c *Conn) contextWithCloseAndWriteDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	operationCtx, cancel := context.WithCancelCause(context.Background())

	detachLifetime := context.AfterFunc(c.closed, func() {
		err := c.closed.Err()
		if err == nil {
			err = context.Canceled
		}
		cancel(err)
	})

	detachDeadline := context.AfterFunc(c.writeDeadline.Context(), func() {
		err := c.writeDeadline.Err()
		if err == nil {
			err = context.DeadlineExceeded
		}
		cancel(err)
	})

	detachCtx := context.AfterFunc(ctx, func() {
		err := ctx.Err()
		if err == nil {
			err = context.Canceled
		}
		cancel(err)
	})

	return operationCtx, func() {
		detachLifetime()
		detachDeadline()
		detachCtx()
		cancel(context.Canceled)
	}
}

func (c *Conn) compactPreparedRecords(records []preparedRecord) []preparedDatagram {
	if len(records) == 0 {
		return []preparedDatagram{}
	}

	totalSize := 0
	for _, record := range records {
		totalSize += len(record.raw)
	}

	datagrams := make([]preparedDatagram, len(records))
	flatRaw := make([]byte, 0, totalSize)

	datagramIndex := 0
	currentSize := 0
	offset := 0

	for _, record := range records {
		recordSize := len(record.raw)

		flatRaw = append(flatRaw, record.raw...)

		if currentSize > 0 && currentSize+recordSize >= c.maximumTransmissionUnit {
			end := offset + currentSize
			datagrams[datagramIndex].raw = flatRaw[offset:end:end]
			datagramIndex++
			offset += currentSize
			currentSize = 0
		}

		currentSize += recordSize

		if record.tracked != nil {
			datagrams[datagramIndex].tracked = append(
				datagrams[datagramIndex].tracked,
				*record.tracked,
			)
		}
	}

	end := offset + currentSize
	datagrams[datagramIndex].raw = flatRaw[offset:end:end]

	return datagrams[:datagramIndex+1]
}

func (c *Conn) prepareRecord(outbound *dtlsflight.Outbound) ([]byte, error) {
	if outbound == nil || outbound.Content == nil || !validProtection(outbound.Protection) {
		return nil, dtlserrors.ErrInvalidPacket
	}
	contentType, plaintext, err := marshalRecordContent(outbound.Content)
	if err != nil {
		return nil, err
	}

	epoch := outbound.Epoch
	seq, err := c.allocateLocalSequenceNumber(epoch)
	if err != nil {
		return nil, err
	}

	return c.encodeRecord(epoch, seq, contentType, plaintext, outbound.Protection)
}

func (c *Conn) allocateLocalSequenceNumber(epoch uint64) (uint64, error) {
	common := dtlsstate.CommonState(c.state)
	if common.LocalVersion != protocol.Version1_3 && epoch > 0xffff {
		return 0, dtlserrors.ErrEpochOverflow
	}

	return common.AllocateLocalSequenceNumber(epoch, recordlayer.MaxSequenceNumber)
}

func marshalRecordContent(content protocol.Content) (protocol.ContentType, []byte, error) {
	switch content.(type) {
	case *handshake.Handshake, *alert.Alert, *protocol.ApplicationData, *protocol.ACK,
		*protocol.ChangeCipherSpec,
		*protocol.ReturnRoutabilityCheck:
	default:
		return 0, nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	plaintext, err := content.Marshal()
	if err != nil {
		return 0, nil, err
	}
	if len(plaintext) > maxPlaintextRecordLen {
		return 0, nil, dtlserrors.ErrInvalidPacketLength
	}

	return content.ContentType(), plaintext, nil
}

func validProtection(protection dtlsflight.Protection) bool {
	return protection == dtlsflight.ProtectionPlaintext || protection == dtlsflight.ProtectionCiphertext
}

func (c *Conn) encodeRecord( //nolint:cyclop
	epoch uint64,
	seq uint64,
	contentType protocol.ContentType,
	plaintext []byte,
	protection dtlsflight.Protection,
) ([]byte, error) {
	if !validProtection(protection) {
		return nil, dtlserrors.ErrInvalidPacket
	}
	if len(plaintext) > maxPlaintextRecordLen {
		return nil, dtlserrors.ErrInvalidPacketLength
	}
	common := dtlsstate.CommonState(c.state)
	if protection == dtlsflight.ProtectionCiphertext && common.LocalVersion == protocol.Version1_3 {
		return c.sealRecordContent(epoch, seq, contentType, plaintext)
	}

	if epoch > 0xffff {
		return nil, dtlserrors.ErrEpochOverflow
	}
	header := recordlayer.RecordConfig{
		Version:        protocol.Version1_2,
		ContentType:    contentType,
		Epoch:          uint16(epoch), //nolint:gosec // Checked before fixed-header encoding.
		SequenceNumber: seq,
	}
	payload := plaintext
	if protection == dtlsflight.ProtectionCiphertext && common.LocalVersion == protocol.Version1_2 && c.state.ShouldWrapConnectionID() {
		if len(plaintext)+1 > maxCIDInnerPlaintextLen {
			return nil, dtlserrors.ErrInvalidPacketLength
		}
		paddingLen := c.paddingLengthGenerator(uint(len(plaintext)))
		if paddingLen > uint(maxCIDInnerPlaintextLen-len(plaintext)-1) { //nolint:gosec // Non-negative and bounded.
			return nil, dtlserrors.ErrInvalidPacketLength
		}
		var err error
		payload, err = recordlayer.MarshalInnerPlaintext(plaintext, contentType, int(paddingLen)) //nolint:gosec // Bounded by maxCIDInnerPlaintextLen above.
		if err != nil {
			return nil, err
		}
		if len(payload) > maxCIDInnerPlaintextLen {
			return nil, dtlserrors.ErrInvalidPacketLength
		}
		header.ContentType = protocol.ContentTypeConnectionID
		header.ConnectionID = bytes.Clone(common.RemoteConnectionID)
	}
	if protection != dtlsflight.ProtectionCiphertext {
		return recordlayer.MarshalRecord(header, payload)
	}
	if common.CipherSuite == nil {
		return nil, dtlserrors.ErrCipherSuiteNotInit
	}
	state12, ok := c.state.(*dtlsstate.State12)
	if !ok || state12.Protection == nil {
		return nil, dtlserrors.ErrCipherSuiteNotInit
	}
	metadata, err := dtlsciphersuite.NewLegacyRecord(header.ContentType, header.Version, header.Epoch, header.SequenceNumber, header.ConnectionID)
	if err != nil {
		return nil, err
	}
	expectedLen, err := common.CipherSuite.Capabilities().ProtectedLen(len(payload))
	if err != nil {
		return nil, err
	}
	protected, err := state12.Seal(metadata, payload)
	if err != nil {
		return nil, err
	}
	if len(protected) != expectedLen {
		return nil, cryptosuite.ErrInvalidCapabilities
	}

	return recordlayer.MarshalRecord(header, protected)
}

func (c *Conn) sealRecordContent( //nolint:cyclop
	epoch uint64,
	seq uint64,
	contentType protocol.ContentType,
	plaintext []byte,
) ([]byte, error) {
	generation, err := c.writeTrafficGeneration(epoch)
	if err != nil {
		return nil, err
	}

	innerPlaintext, err := recordlayer.MarshalInnerPlaintext(plaintext, contentType, 0)
	if err != nil {
		return nil, err
	}
	if len(innerPlaintext) > maxDTLS13InnerPlaintextLen {
		return nil, dtlserrors.ErrInvalidPacketLength
	}
	header := recordlayer.CiphertextConfig{EpochLow: uint8(epoch & 0x3), SequenceNumber: uint16(seq & 0xffff), TwoByteSequence: true, LengthPresent: true}
	if state13, ok := c.state.(*dtlsstate.State13); ok &&
		state13.CID.Negotiated && state13.CID.Send.UseCID {
		header.ConnectionID = bytes.Clone(state13.CID.Send.Active)
	}

	common := dtlsstate.CommonState(c.state)
	if common.CipherSuite == nil {
		return nil, dtlserrors.ErrCipherSuiteNotInit
	}
	capabilities := common.CipherSuite.Capabilities()
	if !capabilities.SupportsVersion(protocol.Version1_3) {
		return nil, cryptosuite.ErrInvalidCapabilities
	}
	protectedLen, err := capabilities.ProtectedLen(len(innerPlaintext))
	if err != nil {
		return nil, err
	}
	// Record-number encryption requires at least 16 bytes of ciphertext, so
	// senders MUST pad short plaintexts to produce a suitable-length ciphertext.
	//
	// https://www.rfc-editor.org/rfc/rfc9147#section-4.2.3
	sampleLen := capabilities.MaskLen()
	if sampleLen <= 0 {
		return nil, cryptosuite.ErrInvalidCapabilities
	}
	if protectedLen < sampleLen {
		innerPlaintext, err = recordlayer.MarshalInnerPlaintext(plaintext, contentType, sampleLen-protectedLen)
		if err != nil {
			return nil, err
		}
		if len(innerPlaintext) > maxDTLS13InnerPlaintextLen {
			return nil, dtlserrors.ErrInvalidPacketLength
		}
		protectedLen, err = capabilities.ProtectedLen(len(innerPlaintext))
		if err != nil {
			return nil, err
		}
	}
	var headerBuffer [260]byte
	clearHeader, err := recordwire.AppendUnifiedHeader(headerBuffer[:0], header.EpochLow, header.SequenceNumber, header.TwoByteSequence, header.ConnectionID, header.LengthPresent, protectedLen)
	if err != nil {
		return nil, err
	}
	metadata, err := dtlsciphersuite.NewUnifiedRecord(epoch, seq, clearHeader, protectedLen)
	if err != nil {
		return nil, err
	}
	protected, err := generation.Seal(metadata, innerPlaintext)
	if err != nil {
		return nil, err
	}
	if len(protected) != protectedLen {
		return nil, cryptosuite.ErrInvalidCapabilities
	}
	if len(protected) < sampleLen {
		return nil, dtlserrors.ErrBufferTooSmall
	}
	mask, err := generation.Protection.Mask(protected[:sampleLen])
	if err != nil {
		return nil, err
	}
	header.SequenceNumber, err = applySequenceNumberMask(
		header.SequenceNumber,
		true,
		mask,
	)
	if err != nil {
		return nil, err
	}

	return recordlayer.MarshalCiphertext(header, protected)
}

func applySequenceNumberMask(
	sequenceNumber uint16,
	twoBytes bool,
	mask []byte,
) (uint16, error) {
	if !twoBytes {
		if len(mask) < 1 {
			return 0, dtlserrors.ErrBufferTooSmall
		}

		return (sequenceNumber ^ uint16(mask[0])) & 0xff, nil
	}
	if len(mask) < 2 {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	return sequenceNumber ^ uint16(mask[0])<<8 ^ uint16(mask[1]), nil
}

func (c *Conn) writeTrafficGeneration(epoch uint64) (*dtlsstate.TrafficGeneration, error) {
	state13, ok := c.state.(*dtlsstate.State13)
	if !ok || state13.TrafficKeys == nil {
		return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}
	generation, ok := state13.TrafficKeys.Write(epoch)
	if !ok || generation.Protection == nil {
		return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	return generation, nil
}

type preparedRecord struct {
	raw     []byte
	tracked *dtlshandshake.SentHandshakeRecord
}

func (c *Conn) prepareHandshakeRecords(outbound *dtlsflight.Outbound, dtlsHandshake *handshake.Handshake) ([]preparedRecord, error) {
	handshakeFragments, err := c.fragmentHandshake(dtlsHandshake)
	if err != nil {
		return nil, err
	}

	rawPackets := make([]preparedRecord, 0, len(handshakeFragments))
	epoch := outbound.Epoch
	for _, handshakeFragment := range handshakeFragments {
		selected, err := selectHandshakeFragment(outbound.HandshakeFragmentOffsets, handshakeFragment)
		if err != nil {
			return nil, err
		}
		if !selected {
			continue
		}
		seq, err := c.allocateLocalSequenceNumber(epoch)
		if err != nil {
			return nil, err
		}
		rawPacket, err := c.encodeRecord(
			epoch,
			seq,
			protocol.ContentTypeHandshake,
			handshakeFragment,
			outbound.Protection,
		)
		if err != nil {
			return nil, err
		}

		prepared := preparedRecord{raw: rawPacket}
		if outbound.TrackACK {
			fragmentHeader := &handshake.Header{}
			if err = fragmentHeader.Unmarshal(handshakeFragment); err != nil {
				return nil, err
			}
			prepared.tracked = &dtlshandshake.SentHandshakeRecord{
				Number:    protocol.RecordNumber{Epoch: epoch, SequenceNumber: seq},
				Fragments: []dtlshandshake.SentHandshakeFragment{{MessageSequence: fragmentHeader.MessageSequence, Offset: fragmentHeader.FragmentOffset, Length: fragmentHeader.FragmentLength}},
			}
		}
		rawPackets = append(rawPackets, prepared)
	}

	return rawPackets, nil
}

func selectHandshakeFragment(offsets map[uint32]uint32, raw []byte) (bool, error) {
	if offsets == nil {
		return true, nil
	}
	header := &handshake.Header{}
	if err := header.Unmarshal(raw); err != nil {
		return false, err
	}
	length, ok := offsets[header.FragmentOffset]

	return ok && length == header.FragmentLength, nil
}

var noContentFragments = [][]byte{ //nolint:gochecknoglobals
	{},
}

func (c *Conn) fragmentHandshake(dtlsHandshake *handshake.Handshake) ([][]byte, error) {
	messageSize := dtlsHandshake.Message.MarshalSize()
	numFragments := max(1, (messageSize-1)/c.maximumTransmissionUnit+1)

	fragmentedHandshakes := make([][]byte, numFragments)

	if numFragments == 1 {
		fragmentedHandshake := make([]byte, handshake.HeaderLength+messageSize)

		headerFragment := handshake.Header{
			Type:            dtlsHandshake.Header.Type,
			Length:          dtlsHandshake.Header.Length,
			MessageSequence: dtlsHandshake.Header.MessageSequence,
			FragmentOffset:  uint32(0),
			FragmentLength:  uint32(messageSize), //nolint:gosec // G115
		}

		_, err := headerFragment.MarshalTo(fragmentedHandshake)
		if err != nil {
			return nil, err
		}

		_, err = dtlsHandshake.Message.MarshalTo(fragmentedHandshake[handshake.HeaderLength:])
		if err != nil {
			return nil, err
		}

		fragmentedHandshakes[0] = fragmentedHandshake

		return fragmentedHandshakes, nil
	}

	content, err := dtlsHandshake.Message.Marshal()
	if err != nil {
		return nil, err
	}

	contentFragments := util.SplitBytes(content, c.maximumTransmissionUnit)
	if len(contentFragments) == 0 {
		contentFragments = noContentFragments
	}

	offset := 0
	for i, contentFragment := range contentFragments {
		contentFragmentLen := len(contentFragment)

		headerFragment := handshake.Header{
			Type:            dtlsHandshake.Header.Type,
			Length:          dtlsHandshake.Header.Length,
			MessageSequence: dtlsHandshake.Header.MessageSequence,
			FragmentOffset:  uint32(offset),
			FragmentLength:  uint32(contentFragmentLen), //nolint:gosec // G115
		}

		fragmentedHandshake := make([]byte, handshake.HeaderLength+contentFragmentLen)

		offset += contentFragmentLen

		_, err := headerFragment.MarshalTo(fragmentedHandshake)
		if err != nil {
			return nil, err
		}

		copy(fragmentedHandshake[handshake.HeaderLength:], contentFragment)

		fragmentedHandshakes[i] = fragmentedHandshake
	}

	return fragmentedHandshakes, nil
}

// readBufferPools caches read buffer pools by size so buffers are reused across
// connections. Only a small bounded set of distinct sizes is expected in a
// program.
var readBufferPools sync.Map //nolint:gochecknoglobals // map[int]*sync.Pool

// readBufferPoolForSize returns the shared read buffer pool for size.
func readBufferPoolForSize(size int) *sync.Pool {
	pool, _ := readBufferPools.LoadOrStore(size, &sync.Pool{
		New: func() any {
			b := make([]byte, size)

			return &b
		},
	})

	return pool.(*sync.Pool) //nolint:forcetypeassert // only *sync.Pool values are stored
}

// injectionEnabled reports whether this connection accepts injected packets.
// Only then does the read loop race the socket read against an injected packet,
// which costs a goroutine and a channel per datagram.
func (c *Conn) injectionEnabled() bool {
	return c.outboundHandshakePacketInterceptor != nil || c.inboundHandshakePacketNotifier != nil
}

// InjectInboundPacket feeds a raw datagram into the connection as if it had been
// received from rAddr. It is the counterpart of the handshake packet interceptor,
// which allows packets to be carried over another transport. It requires that
// interceptor or the inbound notifier to be set and does nothing otherwise.
// It does not retain p.
func (c *Conn) InjectInboundPacket(p []byte, rAddr net.Addr) {
	if !c.injectionEnabled() {
		c.log.Warnf("dropping injected packet, no handshake packet interceptor or notifier is set")

		return
	}

	// The release is tied to the FSM asking for the next datagram, which can
	// happen while this one is still being processed, so take an owned copy.
	done := make(chan struct{})
	select {
	case c.inboundPacketInject <- injectedPkt{addrPkt{rAddr: rAddr, data: bytes.Clone(p)}, done}:
	case <-c.closed.Done():
		return
	}
	c.closeLock.Lock()
	handshakeDone := c.handshakeDone
	c.closeLock.Unlock()

	select {
	case <-done:
	case <-handshakeDone:
	case <-c.closed.Done():
	}
}

func (c *Conn) finishInject() {
	c.injectMu.Lock()
	defer c.injectMu.Unlock()

	if c.injectDone != nil {
		close(c.injectDone)
		c.injectDone = nil
	}
}

func (c *Conn) readAndBuffer(ctx context.Context) error {
	summary, err := c.readAndProcessDatagram(ctx)
	if err != nil {
		return err
	}
	if !summary.containsHandshake && len(summary.receivedACKs) == 0 {
		c.signalHandshakeQuiescent()

		return nil
	}

	s := dtlshandshake.RecvHandshakeState{Done: make(chan struct{}), HasHandshake: summary.containsHandshake, IsRetransmit: summary.retransmit, ACKs: summary.receivedACKs, RecordsToACK: c.takePendingACKs()}
	select {
	case c.handshakeRecv <- s:
		// If the other party may retransmit the flight,
		// we should respond even if it not a new message.
		<-s.Done
	case <-c.fsm.Done():
	}

	return nil
}

type readResult struct {
	bufptr *[]byte
	length int
	rAddr  net.Addr
	err    error
}

// readDatagram reads the next datagram, either from the underlying connection or
// from a packet injected via InjectInboundPacket. The socket read outlives this
// call when an injected packet wins the race, so it is kept in c.pendingRead and
// picked up by the next call. Callers are serialized by the read loop.
func (c *Conn) readDatagram(ctx context.Context) ([]byte, net.Addr, readBufferLease, error) {
	if c.detached != nil || !c.injectionEnabled() {
		return c.readDatagramFromConn(ctx)
	}

	if c.pendingRead == nil {
		c.pendingRead = c.startDatagramRead(ctx)
	}

	select {
	case injected := <-c.inboundPacketInject:
		c.injectMu.Lock()
		c.injectDone = injected.done
		c.injectMu.Unlock()

		return injected.data, injected.rAddr, readBufferLease{conn: c}, nil
	case res := <-c.pendingRead:
		c.pendingRead = nil
		if res.bufptr == nil {
			return nil, nil, readBufferLease{conn: c}, res.err
		}

		return (*res.bufptr)[:res.length], res.rAddr,
			readBufferLease{conn: c, pool: c.readBufferPool, recyclableReadBuffer: res.bufptr}, res.err
	case <-ctx.Done():
		return nil, nil, readBufferLease{conn: c}, ctx.Err()
	}
}

func (c *Conn) startDatagramRead(ctx context.Context) chan readResult {
	readCh := make(chan readResult, 1)
	go func() {
		bufptr, ok := c.readBufferPool.Get().(*[]byte)
		if !ok {
			readCh <- readResult{err: dtlserrors.ErrFailedToAccessPoolReadBuffer}

			return
		}

		i, rAddr, err := c.nextConn.ReadFromContext(ctx, *bufptr)
		if err != nil && !idtlsnet.IsShortBuffer(err) {
			c.readBufferPool.Put(bufptr)
			readCh <- readResult{err: err}

			return
		}

		readCh <- readResult{bufptr: bufptr, length: i, rAddr: rAddr, err: err}
	}()

	return readCh
}

// readDatagramFromConn reads the next datagram straight from the underlying
// connection, or from the detached conn, without the goroutine the injection
// race needs.
func (c *Conn) readDatagramFromConn(ctx context.Context) ([]byte, net.Addr, readBufferLease, error) {
	bufptr, ok := c.readBufferPool.Get().(*[]byte)
	if !ok {
		return nil, nil, readBufferLease{conn: c}, dtlserrors.ErrFailedToAccessPoolReadBuffer
	}
	lease := readBufferLease{conn: c, pool: c.readBufferPool, recyclableReadBuffer: bufptr}

	var (
		i     int
		rAddr net.Addr
		err   error
	)
	if c.detached != nil {
		i, rAddr, err = c.detached.readDatagram(ctx, *bufptr)
	} else {
		i, rAddr, err = c.nextConn.ReadFromContext(ctx, *bufptr)
	}
	if err != nil && !idtlsnet.IsShortBuffer(err) {
		return nil, nil, lease, err
	}

	return (*bufptr)[:i], rAddr, lease, err
}

func (c *Conn) readAndProcessDatagram(ctx context.Context) (datagramProcessingSummary, error) { //nolint:cyclop
	buf, rAddr, bufferLease, err := c.readDatagram(ctx)
	defer bufferLease.releaseReadBuffer()

	if idtlsnet.IsShortBuffer(err) {
		c.log.Debugf("receive buffer too small (%d bytes); received %d bytes from %v: %v", cap(buf), len(buf), rAddr, err)
		// windows UDP reads can return a truncated prefix without its sender address.
		if len(buf) == 0 || rAddr == nil {
			return datagramProcessingSummary{}, nil
		}
	} else if err != nil {
		return datagramProcessingSummary{}, netError(err)
	}

	return c.processDatagram(ctx, buf, rAddr, &bufferLease)
}

func (c *Conn) processDatagram(ctx context.Context, datagram []byte, rAddr net.Addr, bufferLease *readBufferLease) (datagramProcessingSummary, error) {
	pkts, err := c.unpackDatagram(datagram)
	if len(pkts) == 0 {
		// Discards incomplete records or missing CIDs without terminating the handshake.
		if errors.Is(err, recordlayer.ErrInvalidPacketLength) || errors.Is(err, dtlserrors.ErrInvalidCiphertextHeader) {
			c.log.Debugf("discarded datagram: %v", err)

			return datagramProcessingSummary{}, nil
		}

		return datagramProcessingSummary{}, err
	}

	if err != nil {
		c.log.Debugf("discarded malformed datagram suffix: %v", err)
	}

	summary, err := c.processDatagramPackets(ctx, pkts, rAddr, bufferLease)
	if err != nil {
		return summary, err
	}

	if summary.containsHandshake && c.inboundHandshakePacketNotifier != nil {
		// datagram is only valid for the duration of the callback.
		c.inboundHandshakePacketNotifier(datagram)
	}

	return summary, nil
}

func (c *Conn) processDatagramPackets(ctx context.Context, pkts [][]byte, rAddr net.Addr, bufferLease *readBufferLease) (datagramProcessingSummary, error) {
	datagramContainsCID := recordsContainCID(pkts)
	bufferLease.pendingCID = c.pendingCIDNegotiation()
	if bufferLease.pendingCID {
		datagramContainsCID = false
		for _, p := range pkts {
			if protocol.IsDTLS13Ciphertext(protocol.ContentType(p[0])) && p[0]&recordwire.CIDBit != 0 {
				datagramContainsCID = true

				break
			}
		}
	}
	bufferLease.datagramContainsCID = datagramContainsCID

	var summary datagramProcessingSummary
	for _, p := range pkts {
		outcome, err := c.processIncomingPacket(ctx, p, rAddr, bufferLease, datagramContainsCID)
		if err != nil {
			return datagramProcessingSummary{}, err
		}
		summary.containsHandshake = summary.containsHandshake || outcome.containsHandshake
		summary.retransmit = summary.retransmit || outcome.retransmit
		if outcome.receivedACK != nil {
			summary.receivedACKs = append(summary.receivedACKs, *outcome.receivedACK)
		}
	}

	return summary, nil
}

func (c *Conn) handleQueuedPackets(ctx context.Context) error {
	if c.pendingCIDNegotiation() {
		return nil
	}

	c.lock.Lock()
	pkts := c.encryptedPackets
	c.encryptedPackets = nil
	c.lock.Unlock()

	for _, p := range pkts {
		if p.pendingCID && c.inboundCIDRequired() && !p.datagramContainsCID {
			continue
		}
		_, err := c.processIncomingPacket(
			ctx,
			p.data,
			p.rAddr,
			nil, // don't re-enqueue
			p.datagramContainsCID,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Conn) enqueueEncryptedPackets(packet addrPkt) bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	if len(c.encryptedPackets) >= maxAppDataPacketQueueSize {
		return false
	}

	// scanned records borrow the read datagram
	packet.data = bytes.Clone(packet.data)
	packet.data = packet.data[:len(packet.data):len(packet.data)]
	c.encryptedPackets = append(c.encryptedPackets, packet)

	return true
}

func (c *Conn) maxQueueableFutureEpoch(remoteEpoch uint64) uint64 {
	if remoteEpoch == ^uint64(0) {
		return remoteEpoch
	}
	maxEpoch := remoteEpoch + 1
	if remoteEpoch >= dtlsflight13.EpochHandshake {
		return maxEpoch
	}
	if dtlsstate.CommonState(c.state).LocalVersion == protocol.Version1_3 {
		return dtlsflight13.EpochHandshake
	}
	if dtlsstate.CommonState(c.state).LocalVersion != 0 {
		return maxEpoch
	}
	if c.handshakeConfig != nil && c.handshakeConfig.MaxVersion == protocol.Version1_3 {
		return dtlsflight13.EpochHandshake
	}

	return maxEpoch
}

func (c *Conn) unpackDatagram(buf []byte) ([][]byte, error) {
	if len(buf) == 0 {
		return nil, nil
	}

	common := dtlsstate.CommonState(c.state)
	localCID := common.LocalConnectionIDForInboundRecords()
	cidLength := len(localCID)
	if state, ok := c.state.(*dtlsstate.State13); ok && state.CID.Negotiated {
		cidLength = state.CID.Receive.Length
	}
	config := recordlayer.UnpackDatagramConfig{TargetVersion: common.LocalVersion, CIDLength: cidLength, CIDRequired: c.inboundCIDRequired()}
	records, err := recordlayer.UnpackDatagram(buf, config)
	if cidLength == 0 {
		return records, err
	}

	for i, record := range records {
		cid := recordConnectionID(record, cidLength)
		if len(cid) == 0 {
			continue
		}
		if !c.acceptsInboundCID(cid) {
			// Without a matching CID, protected siblings cannot inherit this
			// association from an unrecognized later record.
			if config.CIDRequired && !recordsContainCID(records[:i]) {
				return nil, dtlserrors.ErrInvalidCiphertextHeader
			}

			return records[:i], nil
		}
	}

	return records, err
}

func (c *Conn) inboundCIDRequired() bool {
	common := dtlsstate.CommonState(c.state)
	if common.LocalVersion == protocol.Version1_3 {
		state13, ok := c.state.(*dtlsstate.State13)

		return ok && state13.CID.Negotiated && state13.CID.Receive.Expected
	}
	if common.LocalVersion == protocol.Version1_2 {
		return len(common.LocalConnectionID()) > 0
	}

	return false
}

func recordsContainCID(records [][]byte) bool {
	for _, record := range records {
		contentType := protocol.ContentType(record[0])
		if contentType == protocol.ContentTypeConnectionID || protocol.IsDTLS13Ciphertext(contentType) && record[0]&recordwire.CIDBit != 0 {
			return true
		}
	}

	return false
}

func (c *Conn) queueableCiphertextEpoch(epochLow uint8, remoteEpoch uint64) bool {
	maximum := c.maxQueueableFutureEpoch(remoteEpoch)
	for epoch := remoteEpoch; epoch < maximum; {
		epoch++
		if uint8(epoch&recordwire.EpochMask) == epochLow {
			return true
		}
	}

	return false
}

func (c *Conn) unmarshalCiphertextRecord(
	buf []byte,
	datagramContainsCID bool,
) (recordlayer.ParsedRecord, error) {
	record := recordlayer.ParsedRecord{}
	hasCID := buf[0]&recordwire.CIDBit != 0
	localCID := dtlsstate.CommonState(c.state).LocalConnectionIDForInboundRecords()
	cidExpected, cidAllowed, err := c.ciphertextCIDPolicy(localCID)
	if err != nil {
		return record, err
	}
	if hasCID && !cidAllowed {
		return record, dtlserrors.ErrInvalidCiphertextHeader
	}
	record, err = recordlayer.ParseRecord(buf, len(localCID))
	if err != nil {
		return record, err
	}
	if cidExpected && !hasCID && !datagramContainsCID {
		return record, dtlserrors.ErrInvalidCiphertextHeader
	}
	if hasCID {
		if !c.acceptsInboundCID(record.ConnectionID()) {
			return record, dtlserrors.ErrInvalidCiphertextHeader
		}
	}

	return record, nil
}

func (c *Conn) ciphertextCIDPolicy(localCID []byte) (expected, allowed bool, err error) {
	state13, ok := c.state.(*dtlsstate.State13)
	if !ok || !state13.CID.Negotiated {
		return false, len(localCID) > 0, nil
	}
	if state13.CID.Receive.Length != len(localCID) {
		return false, false, dtlserrors.ErrInvalidCiphertextHeader
	}

	return state13.CID.Receive.Expected, state13.CID.Receive.Expected, nil
}

type openedRecord struct {
	Content  []byte
	RealType protocol.ContentType
}

func (c *Conn) openCiphertextRecord(record recordlayer.ParsedRecord) (openedRecord, uint64, uint64, error) {
	state13, ok := c.state.(*dtlsstate.State13)
	if !ok || state13.TrafficKeys == nil {
		return openedRecord{}, 0, 0, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}
	generation, ok := state13.TrafficKeys.ReadCandidate(record.EpochLow(), state13.RemoteEpoch())
	if !ok {
		return openedRecord{}, 0, 0, dtlserrors.ErrInvalidEpoch
	}
	if generation.Protection == nil {
		return openedRecord{}, 0, 0, operationalProtectionError(dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented)
	}
	plaintext, sequence, err := c.openCiphertextWithGeneration(record, generation)
	if err != nil {
		return openedRecord{}, 0, 0, err
	}

	return plaintext, sequence, generation.Epoch, nil
}

func (c *Conn) openCiphertextWithGeneration( //nolint:cyclop
	record recordlayer.ParsedRecord,
	generation *dtlsstate.TrafficGeneration,
) (openedRecord, uint64, error) {
	common := dtlsstate.CommonState(c.state)
	if common.CipherSuite == nil {
		return openedRecord{}, 0, operationalProtectionError(dtlserrors.ErrCipherSuiteNotInit)
	}
	capabilities := common.CipherSuite.Capabilities()
	_, err := capabilities.PlaintextLenUpperBound(len(record.Payload()))
	if err != nil {
		return openedRecord{}, 0, errRecordAuthentication
	}
	sampleLen := capabilities.MaskLen()
	if sampleLen <= 0 || len(record.Payload()) < sampleLen {
		return openedRecord{}, 0, errRecordAuthentication
	}
	mask, err := generation.Protection.Mask(record.Payload()[:sampleLen])
	if err != nil {
		return openedRecord{}, 0, operationalProtectionError(err)
	}
	clearSequence, err := applySequenceNumberMask(uint16(record.SequenceNumber()&0xffff), record.SequenceBytes() == 2, mask)
	if err != nil {
		return openedRecord{}, 0, operationalProtectionError(err)
	}
	var headerBuffer [260]byte
	clearHeader := headerBuffer[:len(record.HeaderBytes())]
	copy(clearHeader, record.HeaderBytes())
	sequenceOffset := 1 + len(record.ConnectionID())
	if record.SequenceBytes() == 2 {
		clearHeader[sequenceOffset] = byte(clearSequence >> 8)
		sequenceOffset++
	}
	clearHeader[sequenceOffset] = byte(clearSequence & 0xff)
	highest, _ := common.HighestRemoteSequenceNumber(generation.Epoch)
	sequenceNumber := reconstructSequenceNumber(clearSequence, record.SequenceBytes() == 2, highest)
	metadata, err := dtlsciphersuite.NewUnifiedRecord(generation.Epoch, sequenceNumber, clearHeader, len(record.Payload()))
	if err != nil {
		return openedRecord{}, 0, operationalProtectionError(err)
	}
	plaintext, err := generation.Open(metadata, record.Payload())
	if errors.Is(err, cryptosuite.ErrAuthenticationFailed) {
		return openedRecord{}, 0, errRecordAuthentication
	}
	if err != nil {
		return openedRecord{}, 0, operationalProtectionError(err)
	}
	if len(plaintext) > maxDTLS13InnerPlaintextLen {
		return openedRecord{}, 0, errRecordAuthentication
	}
	if lengthErr := capabilities.ValidatePlaintextLen(len(record.Payload()), len(plaintext)); lengthErr != nil {
		return openedRecord{}, 0, operationalProtectionError(lengthErr)
	}

	common.UpdateRemoteSequenceNumber(generation.Epoch, sequenceNumber)

	content, realType, _, err := recordlayer.ParseInnerPlaintext(plaintext)
	innerPlaintext := openedRecord{Content: content, RealType: realType}
	if err != nil {
		return openedRecord{}, 0, err
	}
	if len(innerPlaintext.Content) > maxPlaintextRecordLen {
		return openedRecord{}, 0, dtlserrors.ErrInvalidPacketLength
	}

	switch innerPlaintext.RealType {
	case protocol.ContentTypeAlert,
		protocol.ContentTypeHandshake,
		protocol.ContentTypeApplicationData,
		protocol.ContentTypeACK,
		protocol.ContentTypeReturnRoutabilityCheck:
		return innerPlaintext, sequenceNumber, nil
	default:
		return openedRecord{}, 0, dtlserrors.ErrInvalidContentType
	}
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

func (c *Conn) prepareIncomingPacket(buf []byte, rAddr net.Addr, bufferLease *readBufferLease, datagramContainsCID bool) (incomingPacketState, bool, error) {
	if protocol.IsDTLS13Ciphertext(protocol.ContentType(buf[0])) {
		version := dtlsstate.CommonState(c.state).LocalVersion
		if version != 0 && version != protocol.Version1_3 {
			c.log.Debug("discarded DTLS 1.3 ciphertext on a DTLS 1.2 connection")

			return incomingPacketState{}, false, nil
		}

		return c.prepareCiphertextPacket(buf, rAddr, bufferLease, datagramContainsCID)
	}
	if dtlsstate.CommonState(c.state).LocalVersion == protocol.Version1_3 && (!isPlaintextRecord13ContentType(protocol.ContentType(buf[0])) || len(buf) < recordlayer.FixedHeaderSize || buf[3] != 0 || buf[4] != 0) {
		c.log.Debug("discarded invalid DTLS 1.3 plaintext record")

		return incomingPacketState{}, false, nil
	}

	return c.prepareLegacyPacket(buf, rAddr, bufferLease)
}

func isPlaintextRecord13ContentType(contentType protocol.ContentType) bool {
	return contentType == protocol.ContentTypeAlert || contentType == protocol.ContentTypeHandshake || contentType == protocol.ContentTypeACK
}

func (c *Conn) prepareCiphertextPacket(buf []byte, rAddr net.Addr, bufferLease *readBufferLease, datagramContainsCID bool) (incomingPacketState, bool, error) {
	ciphertext, err := c.unmarshalCiphertextRecord(buf, datagramContainsCID)
	if err != nil {
		c.log.Debugf("discarded broken ciphertext packet: %v", err)

		return incomingPacketState{}, false, nil
	}

	if c.queueIfCipherSuiteUninitialized(
		rAddr,
		buf,
		bufferLease,
		"handshake not finished, queuing ciphertext packet",
	) {
		return incomingPacketState{}, false, nil
	}

	innerPlaintext, sequenceNumber, epoch, err := c.openCiphertextRecord(ciphertext)
	if err != nil {
		if errors.Is(err, errRecordOperational) {
			return incomingPacketState{}, false, err
		}
		if errors.Is(err, dtlserrors.ErrInvalidEpoch) {
			c.handleFutureCiphertextPacket(ciphertext.EpochLow(), dtlsstate.CommonState(c.state).RemoteEpoch(), rAddr, buf, bufferLease)
		}
		c.log.Debugf("%s: decrypt failed: %s", srvCliStr(dtlsstate.CommonState(c.state).IsClient), err)

		return incomingPacketState{}, false, nil
	}

	markPacketAsValid, ok := c.replayMarker(epoch, sequenceNumber, ^uint64(0))
	if !ok {
		return incomingPacketState{}, false, nil
	}

	prepared := incomingPacketState{
		raw:               buf,
		content:           innerPlaintext.Content,
		contentType:       innerPlaintext.RealType,
		number:            protocol.RecordNumber{Epoch: epoch, SequenceNumber: sequenceNumber},
		markPacketAsValid: markPacketAsValid,
		// The datagram's source address remains a candidate until the CID and
		// ciphertext have both been authenticated and replay checks confirm this
		// is the latest valid record.
		// https://datatracker.ietf.org/doc/html/rfc9146#section-6
		originalCID: len(ciphertext.ConnectionID()) > 0,
	}

	return prepared, true, nil
}

func (c *Conn) handleFutureCiphertextPacket(epochLow uint8, remoteEpoch uint64, rAddr net.Addr, buf []byte, bufferLease *readBufferLease) {
	if !c.queueableCiphertextEpoch(epochLow, remoteEpoch) {
		c.log.Debugf("discarded future ciphertext packet (epoch low: %d)", epochLow)

		return
	}
	if bufferLease != nil {
		if ok := bufferLease.enqueue(addrPkt{rAddr: rAddr, data: buf}); ok {
			c.log.Debug("received ciphertext packet of next epoch, queuing packet")
		}
	}
}

func (c *Conn) replayMarker(epoch, sequenceNumber, maximum uint64) (func() bool, bool) {
	common := dtlsstate.CommonState(c.state)
	if common.ReplayDetector == nil {
		common.ReplayDetector = make(map[uint64]replaydetector.ReplayDetector)
	}
	if common.ReplayDetector[epoch] == nil {
		common.ReplayDetector[epoch] = replaydetector.New(c.replayProtectionWindow, maximum)
	}
	accept, ok := common.ReplayDetector[epoch].Check(sequenceNumber)
	if !ok {
		c.log.Debugf("discarded duplicated packet (epoch: %d, seq: %d)", epoch, sequenceNumber)

		return nil, false
	}

	return accept, true
}

func (c *Conn) queueIfCipherSuiteUninitialized(rAddr net.Addr, buf []byte, bufferLease *readBufferLease, message string) bool {
	if c.hasInboundRecordProtection() {
		return false
	}
	if bufferLease != nil {
		if ok := bufferLease.enqueue(addrPkt{rAddr: rAddr, data: buf}); ok {
			c.log.Debug(message)
		}
	}

	return true
}

func (c *Conn) hasInboundRecordProtection() bool {
	common := dtlsstate.CommonState(c.state)
	if state13, ok := c.state.(*dtlsstate.State13); ok && common.LocalVersion == protocol.Version1_3 {
		if state13.TrafficKeys == nil {
			return false
		}
		generation, found := state13.TrafficKeys.Read(common.RemoteEpoch())

		return found && generation.Protection != nil
	}

	state12, ok := c.state.(*dtlsstate.State12)

	return ok && common.CipherSuite != nil && state12.Protection != nil
}

//nolint:cyclop
func (c *Conn) prepareLegacyPacket(buf []byte, rAddr net.Addr, bufferLease *readBufferLease) (incomingPacketState, bool, error) {
	raw := buf
	header, ok := c.unmarshalLegacyHeader(buf)
	if !ok {
		return incomingPacketState{}, false, nil
	}
	// Discard old epoch-zero alerts following the earlier-epoch discard recommendation:
	// https://datatracker.ietf.org/doc/html/rfc9147#section-4.2.1
	// DTLS 1.2 requires accepting old epochs until the handshake completes:
	// https://datatracker.ietf.org/doc/html/rfc6347#section-4.1
	common := dtlsstate.CommonState(c.state)
	if header.Epoch() == 0 && header.ContentType() == protocol.ContentTypeAlert && common.RemoteEpoch() != 0 &&
		(common.LocalVersion == protocol.Version1_3 || c.isHandshakeCompletedSuccessfully()) {
		c.log.Debug("discarded alert from the old plaintext epoch")

		return incomingPacketState{}, false, nil
	}
	if c.handleFutureLegacyPacket(header, rAddr, buf, bufferLease) {
		return incomingPacketState{}, false, nil
	}

	markPacketAsValid, ok := c.replayMarker(uint64(header.Epoch()), header.SequenceNumber(), recordlayer.MaxSequenceNumber)
	if !ok {
		return incomingPacketState{}, false, nil
	}

	contentType := header.ContentType()
	content := header.Payload()
	originalCID := false
	if header.Epoch() != 0 {
		var decryptOK bool
		var err error
		contentType, content, originalCID, decryptOK, err = c.decryptLegacyPacket(header, buf, rAddr, bufferLease)
		if err != nil {
			return incomingPacketState{}, false, err
		}
		if !decryptOK {
			return incomingPacketState{}, false, nil
		}
	}

	return incomingPacketState{raw: raw, content: content, contentType: contentType, number: protocol.RecordNumber{Epoch: uint64(header.Epoch()), SequenceNumber: header.SequenceNumber()}, markPacketAsValid: markPacketAsValid, originalCID: originalCID}, true, nil
}

func (c *Conn) unmarshalLegacyHeader(buf []byte) (recordlayer.ParsedRecord, bool) {
	localCID := dtlsstate.CommonState(c.state).LocalConnectionIDForInboundRecords()
	header, err := recordlayer.ParseRecord(buf, len(localCID))
	if err != nil {
		// Decode error must be silently discarded
		// [RFC6347 Section-4.1.2.7]
		c.log.Debugf("discarded broken packet: %v", err)

		return recordlayer.ParsedRecord{}, false
	}

	return header, true
}

func (c *Conn) handleFutureLegacyPacket(header recordlayer.ParsedRecord, rAddr net.Addr, buf []byte, bufferLease *readBufferLease) bool {
	remoteEpoch := dtlsstate.CommonState(c.state).RemoteEpoch()
	if uint64(header.Epoch()) <= remoteEpoch {
		return false
	}
	if uint64(header.Epoch()) > c.maxQueueableFutureEpoch(remoteEpoch) {
		c.log.Debugf("discarded future packet (epoch: %d, seq: %d)",
			header.Epoch(), header.SequenceNumber(),
		)

		return true
	}
	if bufferLease != nil {
		if ok := bufferLease.enqueue(addrPkt{rAddr: rAddr, data: buf}); ok {
			c.log.Debug("received packet of next epoch, queuing packet")
		}
	}

	return true
}

func (c *Conn) decryptLegacyPacket(header recordlayer.ParsedRecord, buf []byte, rAddr net.Addr, bufferLease *readBufferLease) (protocol.ContentType, []byte, bool, bool, error) {
	if c.queueIfCipherSuiteUninitialized(
		rAddr,
		buf,
		bufferLease,
		"handshake not finished, queuing packet",
	) {
		return 0, nil, false, false, nil
	}

	if !c.validateLegacyCIDPresence(header) {
		return 0, nil, false, false, nil
	}

	decrypted, err := c.decryptLegacyRecord(header, header.Payload())
	if err != nil {
		if errors.Is(err, errRecordOperational) {
			return 0, nil, false, false, err
		}
		c.log.Debugf("%s: decrypt failed: %s", srvCliStr(dtlsstate.CommonState(c.state).IsClient), err)

		return 0, nil, false, false, nil
	}
	content := decrypted

	if header.ContentType() == protocol.ContentTypeConnectionID {
		innerContent, realType, _, err := recordlayer.ParseInnerPlaintext(content)
		if err != nil {
			c.log.Debugf("unpacking inner plaintext failed: %s", err)

			return 0, nil, false, false, nil
		}
		if len(innerContent) > maxPlaintextRecordLen {
			c.log.Debug("discarded oversized inner plaintext")

			return 0, nil, false, false, nil
		}

		return realType, innerContent, true, c.validateLegacyCID(header), nil
	}

	return header.ContentType(), content, false, c.validateLegacyCID(header), nil
}

func (c *Conn) validateLegacyCIDPresence(header recordlayer.ParsedRecord) bool {
	common := dtlsstate.CommonState(c.state)
	if len(common.LocalConnectionIDForInboundRecords()) == 0 || header.ContentType() == protocol.ContentTypeConnectionID {
		return true
	}

	c.log.Debug("discarded packet missing connection ID after value negotiated")

	return false
}

func (c *Conn) decryptLegacyRecord( //nolint:cyclop
	header recordlayer.ParsedRecord,
	protected []byte,
) ([]byte, error) {
	state12, ok := c.state.(*dtlsstate.State12)
	common := dtlsstate.CommonState(c.state)
	if !ok || common.CipherSuite == nil || state12.Protection == nil {
		return nil, operationalProtectionError(dtlserrors.ErrCipherSuiteNotInit)
	}
	metadata, err := dtlsciphersuite.NewLegacyRecord(header.ContentType(), header.Version(), header.Epoch(), header.SequenceNumber(), header.ConnectionID())
	if err != nil {
		return nil, errRecordAuthentication
	}
	capabilities := common.CipherSuite.Capabilities()
	_, err = capabilities.PlaintextLenUpperBound(len(protected))
	if err != nil {
		return nil, errRecordAuthentication
	}
	plaintext, err := state12.Open(metadata, protected)
	if errors.Is(err, cryptosuite.ErrAuthenticationFailed) {
		return nil, errRecordAuthentication
	}
	if err != nil {
		return nil, operationalProtectionError(err)
	}
	if len(plaintext) > maxPlaintextRecordLen {
		return nil, errRecordAuthentication
	}
	if err = capabilities.ValidatePlaintextLen(len(protected), len(plaintext)); err != nil {
		return nil, operationalProtectionError(err)
	}

	return plaintext, nil
}

func (c *Conn) validateLegacyCID(header recordlayer.ParsedRecord) bool {
	if bytes.Equal(dtlsstate.CommonState(c.state).LocalConnectionIDForInboundRecords(), header.ConnectionID()) {
		return true
	}

	c.log.Debug("unexpected connection ID")

	return false
}

func (c *Conn) bufferHandshakeRecord(content []byte, number protocol.RecordNumber, markPacketAsValid func() bool) (packetOutcome, bool) {
	c.syncFragmentBufferHandshakeSequence()
	isRetransmit, err := c.fragmentBuffer.Push(number.Epoch, content)
	if err != nil {
		// Decode error must be silently discarded
		// [RFC6347 Section-4.1.2.7]
		c.log.Debugf("defragment failed: %s", err)

		return packetOutcome{}, false
	}

	isLatestSeqNum := markPacketAsValid()
	if dtlsstate.CommonState(c.state).LocalVersion == protocol.Version1_3 &&
		number.Epoch >= dtlsflight13.EpochHandshake {
		c.lock.Lock()
		c.queueHandshakeACK(content, number)
		c.lock.Unlock()
	}

	for out, epoch := c.fragmentBuffer.Pop(); out != nil; out, epoch = c.fragmentBuffer.Pop() {
		header := &handshake.Header{}
		if err := header.Unmarshal(out); err != nil {
			c.log.Debugf("%s: handshake parse failed: %s", srvCliStr(dtlsstate.CommonState(c.state).IsClient), err)

			continue
		}
		c.handshakeCache.Push(out, epoch, header.MessageSequence, header.Type, !dtlsstate.CommonState(c.state).IsClient)
	}

	return packetOutcome{containsHandshake: true, retransmit: isRetransmit}, isLatestSeqNum
}

func (c *Conn) handleChangeCipherSpecRecord(prepared incomingPacketState, rAddr net.Addr, bufferLease *readBufferLease) bool {
	common := dtlsstate.CommonState(c.state)
	if !c.hasInboundRecordProtection() {
		if bufferLease != nil {
			if ok := bufferLease.enqueue(addrPkt{rAddr: rAddr, data: prepared.raw}); ok {
				c.log.Debugf("CipherSuite not initialized, queuing packet")
			}
		}

		return false
	}

	if prepared.number.Epoch >= 0xffff {
		return false
	}
	newRemoteEpoch := prepared.number.Epoch + 1
	c.log.Tracef("%s: <- ChangeCipherSpec (epoch: %d)", srvCliStr(common.IsClient), newRemoteEpoch)
	if common.RemoteEpoch() != prepared.number.Epoch {
		return false
	}

	c.setRemoteEpoch(newRemoteEpoch)

	return prepared.markPacketAsValid()
}

func (c *Conn) handleApplicationDataRecord(ctx context.Context, content *protocol.ApplicationData, prepared incomingPacketState) (bool, packetOutcome, error) {
	if prepared.number.Epoch == 0 {
		return false, packetOutcome{responseAlert: &alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage}}, dtlserrors.ErrApplicationDataEpochZero
	}

	isLatestSeqNum := prepared.markPacketAsValid()
	if c.detached != nil {
		c.detached.publishApplicationData(content.Data)

		return isLatestSeqNum, packetOutcome{}, nil
	}
	select {
	case c.decrypted <- content.Data:
	case <-c.closed.Done():
	case <-ctx.Done():
	}

	return isLatestSeqNum, packetOutcome{}, nil
}

func (c *Conn) handleRecordContent(ctx context.Context, content protocol.Content, prepared incomingPacketState, rAddr net.Addr, bufferLease *readBufferLease) (bool, packetOutcome, error) {
	switch content := content.(type) {
	case *protocol.ACK:
		// The ACK's epoch must be at least that of every acknowledged record.
		// Validate the entire ACK before applying it.
		// https://datatracker.ietf.org/doc/html/rfc9147#section-7
		for _, record := range content.Records {
			if record.Epoch > prepared.number.Epoch {
				c.log.Debug("discarded ACK for a record from a higher epoch")

				return false, packetOutcome{}, nil
			}
		}
		isLatestSeqNum := prepared.markPacketAsValid()

		return isLatestSeqNum, packetOutcome{receivedACK: &protocol.ACK{Records: append([]protocol.RecordNumber(nil), content.Records...)}}, nil
	case *alert.Alert:
		c.log.Tracef("%s: <- %s", srvCliStr(dtlsstate.CommonState(c.state).IsClient), content.String())
		var responseAlert *alert.Alert
		if content.Description == alert.CloseNotify {
			// Respond with a close_notify [RFC5246 Section 7.2.1]
			responseAlert = &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify}
		}
		prepared.markPacketAsValid()

		return false, packetOutcome{responseAlert: responseAlert}, &alertError{content}
	case *protocol.ChangeCipherSpec:
		return c.handleChangeCipherSpecRecord(prepared, rAddr, bufferLease), packetOutcome{}, nil
	case *protocol.ApplicationData:
		return c.handleApplicationDataRecord(ctx, content, prepared)
	case *protocol.ReturnRoutabilityCheck:
		return returnRoutabilityConn{conn: c}.HandleRecord(ctx, content, prepared, rAddr)
	default:
		return false, packetOutcome{responseAlert: &alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage}}, fmt.Errorf("%w: %d", dtlserrors.ErrUnhandledContextType, content.ContentType())
	}
}

func unmarshalRecordContent(contentType protocol.ContentType, data []byte) (protocol.Content, error) {
	var content protocol.Content
	switch contentType {
	case protocol.ContentTypeChangeCipherSpec:
		content = &protocol.ChangeCipherSpec{}
	case protocol.ContentTypeAlert:
		content = &alert.Alert{}
	case protocol.ContentTypeApplicationData:
		content = &protocol.ApplicationData{}
	case protocol.ContentTypeACK:
		content = &protocol.ACK{}
	case protocol.ContentTypeReturnRoutabilityCheck:
		content = &protocol.ReturnRoutabilityCheck{}
	default:
		return nil, dtlserrors.ErrInvalidContentType
	}
	if err := content.Unmarshal(data); err != nil {
		return nil, err
	}

	return content, nil
}

func (c *Conn) handleIncomingPacket(ctx context.Context, buf []byte, rAddr net.Addr, bufferLease *readBufferLease, datagramContainsCID bool) (packetOutcome, error) {
	if len(buf) == 0 {
		return packetOutcome{}, nil
	}

	prepared, ok, err := c.prepareIncomingPacket(buf, rAddr, bufferLease, datagramContainsCID)
	if err != nil {
		return packetOutcome{}, err
	}
	if !ok {
		return packetOutcome{}, nil
	}
	prepared.markPacketAsValid = c.rrc.WrapReplayMarker(prepared.markPacketAsValid, rAddr, len(buf), c.RemoteAddr, c.cidPathMigrationPolicy == CIDPathMigrationRRC && dtlsstate.CommonState(c.state).RRCNegotiated)
	if prepared.contentType == protocol.ContentTypeHandshake {
		outcome, isLatestSeqNum := c.bufferHandshakeRecord(
			prepared.content,
			prepared.number,
			prepared.markPacketAsValid,
		)
		returnRoutabilityConn{conn: c}.HandleCandidate(ctx, dtlsstate.CommonState(c.state).RRCNegotiated, prepared.originalCID, isLatestSeqNum, rAddr)

		return outcome, nil
	}

	content, err := unmarshalRecordContent(prepared.contentType, prepared.content)
	if err != nil {
		return packetOutcome{
			responseAlert: &alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
		}, err
	}

	isLatestSeqNum, outcome, err := c.handleRecordContent(ctx, content, prepared, rAddr, bufferLease)
	if err != nil || outcome.responseAlert != nil {
		return outcome, err
	}

	returnRoutabilityConn{conn: c}.HandleCandidate(ctx, dtlsstate.CommonState(c.state).RRCNegotiated, prepared.originalCID, isLatestSeqNum, rAddr)

	return outcome, nil
}

func (c *Conn) processIncomingPacket(ctx context.Context, buf []byte, rAddr net.Addr, bufferLease *readBufferLease, datagramContainsCID bool) (packetOutcome, error) {
	outcome, err := c.handleIncomingPacket(ctx, buf, rAddr, bufferLease, datagramContainsCID)
	if outcome.responseAlert != nil {
		responseAlert := outcome.responseAlert
		if alertErr := c.notify(ctx, responseAlert.Level, responseAlert.Description); alertErr != nil && err == nil {
			err = alertErr
		}
	}

	var receivedAlert *alertError
	if errors.As(err, &receivedAlert) && receivedAlert.IsFatalOrCloseNotify() {
		return packetOutcome{}, receivedAlert
	}

	return outcome, err
}

func (c *Conn) syncFragmentBufferHandshakeSequence() {
	handshakeRecvSequence := dtlsstate.HandshakeRecvSequence(c.state)
	if c.fragmentBuffer == nil || handshakeRecvSequence <= 0 ||
		handshakeRecvSequence > int(^uint16(0)) {
		return
	}

	c.fragmentBuffer.AdvanceTo(uint16(handshakeRecvSequence))
}

func (c *Conn) recvHandshake() <-chan dtlshandshake.RecvHandshakeState {
	if c.detached != nil && !c.detached.quiescentSkip.CompareAndSwap(true, false) {
		c.detached.markQuiescent()
	}
	c.finishInject()

	return c.handshakeRecv
}

func (c *Conn) signalHandshakeQuiescent() {
	if c.detached != nil {
		c.detached.markQuiescent()
	}
	c.finishInject()
}

func (c *Conn) signalHandshakeTerminated(err error) {
	if c.detached != nil {
		c.detached.connectionTerminated(err)
	}
}

func (c *Conn) notify(ctx context.Context, level alert.Level, desc alert.Description) error {
	common := dtlsstate.CommonState(c.state)
	if level == alert.Fatal && len(common.SessionID) > 0 { //nolint:nestif
		if common.LocalVersion == protocol.Version1_2 {
			// According to the RFC, we need to delete the stored session.
			// https://datatracker.ietf.org/doc/html/rfc5246#section-7.2
			if c.handshakeConfig.HasSessionStore {
				c.log.Tracef("clean invalid session: %s", common.SessionID)
				if err := c.handshakeConfig.DelSession(c.sessionKey()); err != nil {
					return err
				}
			}
		}
	}

	outbound := &dtlsflight.Outbound{
		Epoch: common.LocalEpoch(),
		Content: &alert.Alert{
			Level:       level,
			Description: desc,
		},
	}
	if c.isHandshakeCompletedSuccessfully() {
		outbound.Protection = dtlsflight.ProtectionCiphertext
	}

	return c.writePackets(ctx, []*dtlsflight.Outbound{outbound}, false)
}

func (c *Conn) isHandshakeCompletedSuccessfully() bool {
	return c.handshakeEstablished.Established()
}

func (c *Conn) negotiateVersionServer(ctx context.Context) error {
	for {
		c.signalHandshakeQuiescent()
		if err := c.readAndBufferNoFSM(ctx); err != nil {
			return err
		}
		if ok, err := c.pickVersionFromClientHello(); err != nil {
			var negotiationAlert *alert.Alert
			errors.As(err, &negotiationAlert)
			if alertErr := c.notify(ctx, negotiationAlert.Level, negotiationAlert.Description); alertErr != nil {
				return errors.Join(err, alertErr)
			}

			return err
		} else if ok {
			return nil
		}
		// ClientHello not yet (fully) received; keep reading.
	}
}

//nolint:cyclop
func (c *Conn) negotiateVersionClient(ctx context.Context) ([]*dtlsflight.Outbound, error) {
	gen, _, ok := dtlsflight13.GetGenerator(dtlsflight13.Flight1)
	if !ok {
		return nil, dtlserrors.ErrFlightUnimplemented13
	}
	state13 := dtlsstate.Activate13(c.state)
	c.state = state13
	pkts, dtlsAlert, err := gen(adaptFlightConn(c), state13, c.handshakeCache, c.handshakeConfig)
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
	if err := c.writePackets(ctx, pkts, true); err != nil {
		return nil, err
	}

	for {
		c.signalHandshakeQuiescent()
		if err := c.readAndBufferNoFSM(ctx); err != nil {
			return nil, err
		}
		if ok, err := c.pickVersionFromServerResponse(); err != nil {
			var negotiationAlert *alert.Alert
			errors.As(err, &negotiationAlert)
			if alertErr := c.notify(ctx, negotiationAlert.Level, negotiationAlert.Description); alertErr != nil {
				return nil, errors.Join(err, alertErr)
			}

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
	pull := c.handshakeCache.FullPullMapItems(0, dtlsstate.CommonState(c.state).CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: c.handshakeConfig.InitialEpoch, IsClient: true, Optional: false},
	)
	if pull.Err != nil {
		return false, pull.Err
	}
	if !pull.Ready {
		return false, nil
	}
	ch, ok := pull.Messages[handshake.TypeClientHello].(*handshake.MessageClientHello)
	if !ok {
		return false, nil
	}
	var remote []protocol.Version
	seenSupportedVersions := false
	for _, e := range ch.Extensions {
		if sv, ok := e.(*extension13.OfferedVersions); ok { //nolint:govet
			seenSupportedVersions = true
			remote = sv.Versions

			break
		}
	}
	if !seenSupportedVersions {
		remote = []protocol.Version{ch.Version}
	}

	chosen, ok := dtlsconfig.SelectVersion(remote, c.handshakeConfig.MinVersion, c.handshakeConfig.MaxVersion)
	if !ok {
		return false, fmt.Errorf("%w: %w", dtlserrors.ErrNoCommonProtocolVersion, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion})
	}

	c.setNegotiatedVersion(remote, chosen)

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
	pull := c.handshakeCache.FullPullMapOneOfItems(
		0,
		dtlsstate.CommonState(c.state).CipherSuite,
		dtlsflight.HandshakeCachePullRule{
			Typ: handshake.TypeServerHello, Epoch: c.handshakeConfig.InitialEpoch, IsClient: false,
		},
		dtlsflight.HandshakeCachePullRule{
			Typ: handshake.TypeHelloVerifyRequest, Epoch: c.handshakeConfig.InitialEpoch, IsClient: false,
		},
	)
	if pull.Err != nil {
		return false, pull.Err
	}
	if !pull.Ready {
		return false, nil
	}

	if sh, ok := pull.Messages[handshake.TypeServerHello].(*handshake.MessageServerHello); ok {
		if err := c.pickVersionFromServerHello(sh); err != nil {
			return false, err
		}

		return true, nil
	}

	if hvr, ok := pull.Messages[handshake.TypeHelloVerifyRequest].(*handshake.MessageHelloVerifyRequest); ok {
		if err := c.selectRemoteVersion([]protocol.Version{hvr.Version}); err != nil {
			return false, err
		}

		return true, nil
	}

	return false, nil
}

func (c *Conn) pickVersionFromServerHello(sh *handshake.MessageServerHello) error {
	common := dtlsstate.CommonState(c.state)
	if err := negotiation.ValidateServerHelloResponse(
		common.LocalClientHelloSnapshots.Current(),
		sh,
	); err != nil {
		return err
	}
	remote, err := remoteVersionsFromServerHello(sh)
	if err != nil {
		return err
	}

	return c.selectRemoteVersion(remote)
}

func remoteVersionsFromServerHello(sh *handshake.MessageServerHello) ([]protocol.Version, error) {
	remote, seenSupportedVersions, err := dtlsflight13.ServerHelloSelectedVersions(sh.Extensions)
	if dtlsflight13.IsHelloRetryRequest(sh) {
		return remoteVersionsFromHelloRetryRequest(remote, seenSupportedVersions, err)
	}
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %w",
			err,
			&alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
		)
	}
	if !seenSupportedVersions {
		return []protocol.Version{sh.Version}, nil
	}

	return remote, nil
}

func remoteVersionsFromHelloRetryRequest(remote []protocol.Version, seenSupportedVersions bool, err error) ([]protocol.Version, error) {
	if err != nil {
		return nil, fmt.Errorf("%w: %w", dtlserrors.ErrInvalidHelloRetryRequest, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter})
	}
	if !seenSupportedVersions {
		return nil, fmt.Errorf("%w: %w", dtlserrors.ErrInvalidHelloRetryRequest, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension})
	}
	if remote[0] != protocol.Version1_3 {
		return nil, fmt.Errorf("%w: %w", dtlserrors.ErrUnsupportedProtocolVersion, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion})
	}

	return remote, nil
}

func (c *Conn) selectRemoteVersion(remote []protocol.Version) error {
	chosen, ok := dtlsconfig.SelectVersion(remote, c.handshakeConfig.MinVersion, c.handshakeConfig.MaxVersion)
	if !ok {
		return fmt.Errorf("%w: %w", dtlserrors.ErrNoCommonProtocolVersion, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion})
	}
	c.setNegotiatedVersion(remote, chosen)

	return nil
}

func (c *Conn) setNegotiatedVersion(remote []protocol.Version, chosen protocol.Version) {
	common := dtlsstate.CommonState(c.state)
	common.RemoteVersions = remote
	common.LocalVersion = chosen
	if chosen == protocol.Version1_3 {
		c.state = dtlsstate.Activate13(c.state)

		return
	}

	c.state = dtlsstate.Activate12(c.state)
}

// stampHandshakeSequence assigns the DTLS message_sequence to each handshake
// record in pkts. This is the subset of handshakeFSM.prepare()'s bookkeeping
// that generated dual-stack packets need before being passed to writePackets.
func (c *Conn) stampHandshakeSequence(pkts []*dtlsflight.Outbound) {
	epoch := c.handshakeConfig.InitialEpoch
	for _, p := range pkts {
		p.Epoch += epoch
		if h, ok := p.Content.(*handshake.Handshake); ok {
			h.Header.MessageSequence = dtlsstate.NextHandshakeSendSequence(c.state)
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
// version negotiation phase. It reads and processes a datagram, but does not
// signal an FSM (there is none yet) or wait for its Done channel.
func (c *Conn) readAndBufferNoFSM(ctx context.Context) error {
	defer c.finishInject()

	_, err := c.readAndProcessDatagram(ctx)

	return err
}

func (c *Conn) classifyReadLoopError(err error) readLoopErrorAction {
	var receivedAlert *alertError
	if errors.As(err, &receivedAlert) {
		if receivedAlert.IsFatalOrCloseNotify() {
			return readLoopCloseAndStop
		}
		if c.isHandshakeCompletedSuccessfully() {
			return readLoopDeliverAndContinue
		}

		return readLoopContinue
	}

	switch {
	case errors.Is(err, recordlayer.ErrInvalidPacketLength):
		// Decode error must be silently discarded [RFC6347 Section-4.1.2.7].
		return readLoopContinue
	case errors.Is(err, context.Canceled) && !c.isConnectionClosed():
		return readLoopCloseAndStop
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled),
		errors.Is(err, io.EOF),
		errors.Is(err, net.ErrClosed):
		return readLoopStop
	case c.isHandshakeCompletedSuccessfully():
		return readLoopDeliverAndContinue
	default:
		return readLoopStop
	}
}

func (c *Conn) deliverReadError(ctx context.Context, err error) {
	select {
	case c.decrypted <- err:
	case <-c.closed.Done():
	case <-ctx.Done():
	}
}

//nolint:gocyclo,cyclop,gocognit,contextcheck
func (c *Conn) handshake(ctx context.Context, start handshakeStart) error {
	if dtlsstate.CommonState(c.state).LocalVersion == protocol.Version1_3 {
		if err := c.setupHandshakeFSM13(start); err != nil {
			return err
		}
	} else {
		if err := c.setupHandshakeFSM12(start); err != nil {
			return err
		}
	}

	ctxRead, cancelRead := context.WithCancel(context.Background())
	ctxHs, cancel := context.WithCancel(context.Background())
	if c.detached != nil && start.postSetup != nil {
		c.detached.quiescentSkip.Store(true)
	}

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
		err := c.fsm.Run(ctxHs, handshakeConn{c}, start.fsmState)
		if !errors.Is(err, context.Canceled) {
			c.signalHandshakeTerminated(err)
			select {
			case firstErr <- err:
			default:
			}
		}
	}()

	go func() {
		defer func() {
			if c.isHandshakeCompletedSuccessfully() {
				// Escaping read loop.
				// It's safe to close the decrypted channel now.
				close(c.decrypted)
			}

			// Force stop handshaker when the underlying connection is closed.
			cancel()
		}()
		defer handshakeLoopsFinished.Done()
		if start.postSetup != nil {
			start.postSetup(ctxHs)
		}
		for {
			err := c.readAndBuffer(ctxRead)
			if err == nil {
				continue
			}

			action := c.classifyReadLoopError(err)
			if action == readLoopContinue {
				c.signalHandshakeQuiescent()

				continue
			}
			if action == readLoopDeliverAndContinue {
				c.deliverReadError(ctxRead, err)
				c.signalHandshakeQuiescent()

				continue
			}

			select {
			case firstErr <- err:
			default:
			}

			if !errors.Is(err, context.Canceled) {
				c.signalHandshakeTerminated(err)
			}
			if action == readLoopCloseAndStop {
				if errors.Is(err, context.Canceled) {
					c.log.Trace("handshake timeouts - closing underlying connection")
				}
				_ = c.close(false) //nolint:contextcheck
			}

			return
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
	case <-c.handshakeEstablished.Done():
		return nil
	}
}

func (c *Conn) setupHandshakeFSM13(start handshakeStart) error {
	state13, err := dtlsstate.As13(c.state)
	if err != nil {
		return err
	}
	fsm, err := dtlshandshake.NewFSM13(state13, c.handshakeCache, c.handshakeConfig, start.flight13, start.flights, c.handshakeEstablished)
	if err != nil {
		return err
	}
	c.fsm = fsm

	return nil
}

func (c *Conn) setupHandshakeFSM12(start handshakeStart) error {
	state12, err := dtlsstate.As12(c.state)
	if err != nil {
		return err
	}
	c.fsm = dtlshandshake.NewFSM12(state12, c.handshakeCache, c.handshakeConfig, start.flight12, start.flights, c.handshakeEstablished)

	return nil
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

	if c.isHandshakeCompletedSuccessfully() {
		if byUser {
			// Discard error from notify() to return non-error on user Close()
			// even if the underlying connection is already closed.
			_ = c.notify(context.Background(), alert.Warning, alert.CloseNotify)
		}
		c.clearConnectionIDs()
	}

	if c.detached != nil {
		return nil
	}

	return c.nextConn.Close()
}

func (c *Conn) isConnectionClosed() bool {
	return c.closed.Err() != nil
}

func (c *Conn) setLocalEpoch(epoch uint64) {
	dtlsstate.CommonState(c.state).SetLocalEpoch(epoch)
}

func (c *Conn) setRemoteEpoch(epoch uint64) {
	dtlsstate.CommonState(c.state).SetRemoteEpoch(epoch)
}

func (c *Conn) commitLocalKeyUpdate(generation *dtlsstate.TrafficGeneration) error {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	c.lock.Lock()
	defer c.lock.Unlock()

	state13, ok := c.state.(*dtlsstate.State13)
	if !ok || state13.TrafficKeys == nil {
		return dtlserrors.ErrInvalidProtocolVersionState
	}
	current, _ := state13.TrafficKeys.CurrentWrite()
	if err := validateNextWriteGeneration(current, generation, state13.LocalEpoch()); err != nil {
		return err
	}

	state13.TrafficKeys.Install(generation, nil)
	state13.SetLocalEpoch(generation.Epoch)

	return nil
}

func validateNextWriteGeneration(
	current, next *dtlsstate.TrafficGeneration,
	localEpoch uint64,
) error {
	if current == nil || next == nil {
		return dtlserrors.ErrInvalidEpoch
	}
	if current.Epoch == ^uint64(0) || current.Generation == ^uint64(0) {
		return dtlserrors.ErrEpochOverflow
	}
	if current.Epoch != localEpoch || next.Epoch != current.Epoch+1 || next.Generation != current.Generation+1 {
		return dtlserrors.ErrInvalidEpoch
	}

	return nil
}

// LocalAddr implements net.Conn.LocalAddr.
func (c *Conn) LocalAddr() net.Addr {
	if c.detached != nil {
		return nil
	}

	return c.nextConn.LocalAddr()
}

// RemoteAddr implements net.Conn.RemoteAddr.
func (c *Conn) RemoteAddr() net.Addr {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.rAddr
}

func (c *Conn) sessionKey() []byte {
	common := dtlsstate.CommonState(c.state)
	if common.IsClient {
		// As ServerName can be like 0.example.com, it's better to add
		// delimiter character which is not allowed to be in
		// neither address or domain name.
		return []byte(c.rAddr.String() + "_" + c.handshakeConfig.ServerName)
	}

	return common.SessionID
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
