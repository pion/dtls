// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
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
	"github.com/pion/dtls/v3/internal/extensionnegotiation"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight12 "github.com/pion/dtls/v3/internal/flight/flight12"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsfragmentbuffer "github.com/pion/dtls/v3/internal/fragmentbuffer"
	dtlshandshake "github.com/pion/dtls/v3/internal/handshake"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/pion/transport/v4/deadline"
	"github.com/pion/transport/v4/netctx"
	"github.com/pion/transport/v4/replaydetector"
)

const (
	initialTickerInterval = time.Second
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

// readBufferLease owns a recyclable read buffer until a queued packet view
// takes responsibility for keeping its backing array alive.
type readBufferLease struct {
	conn                 *Conn
	recyclableReadBuffer *[]byte
}

func (w *readBufferLease) enqueue(packet addrPkt) bool {
	if !w.conn.enqueueEncryptedPackets(packet) {
		return false
	}

	w.recyclableReadBuffer = nil

	return true
}

func (w *readBufferLease) releaseReadBuffer() {
	readBuffer := w.recyclableReadBuffer
	w.recyclableReadBuffer = nil
	if readBuffer != nil {
		poolReadBuffer.Put(readBuffer)
	}
}

type incomingPacketState struct {
	buf               []byte
	header            *recordlayer.Header
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
	flights   []*dtlsflight.Packet
	postSetup func(context.Context)
}

type handshakeConn struct {
	conn *Conn
}

func (c handshakeConn) Notify(ctx context.Context, level alert.Level, desc alert.Description) error {
	return c.conn.notify(ctx, level, desc)
}

func (c handshakeConn) WritePackets(
	ctx context.Context,
	pkts []*dtlsflight.Packet,
) (*dtlshandshake.WriteResult, error) {
	return c.conn.writePacketsWithResult(ctx, pkts)
}

func (c handshakeConn) RecvHandshake() <-chan dtlshandshake.RecvHandshakeState {
	return c.conn.recvHandshake()
}

func (c handshakeConn) SetLocalEpoch(epoch uint16) {
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
	fragmentBuffer *dtlsfragmentbuffer.FragmentBuffer // out-of-order and missing fragment handling
	handshakeCache *dtlsflight.Cache                  // caching of handshake messages for verifyData generation
	pendingACKs    []protocol.RecordNumber
	decrypted      chan any // Decrypted Application Data or error, pull by calling `Read`
	rAddr          net.Addr
	state          dtlsstate.Active // active DTLS version state

	maximumTransmissionUnit int
	paddingLengthGenerator  func(uint) uint

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

	reading               chan struct{}
	handshakeRecv         chan dtlshandshake.RecvHandshakeState
	cancelHandshaker      func()
	cancelHandshakeReader func()

	fsm dtlshandshake.FSM

	replayProtectionWindow uint

	handshakeConfig *dtlsconfig.HandshakeConfig
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

	handshakeConfig := newHandshakeConfig(config, configValues, resumeState)
	conn := newConn(nextConn, rAddr, configValues, handshakeConfig, isClient)

	conn.setRemoteEpoch(0)
	conn.setLocalEpoch(0)

	return conn, nil
}

func newConn(
	nextConn net.PacketConn,
	rAddr net.Addr,
	configValues connConfigValues,
	handshakeConfig *dtlsconfig.HandshakeConfig,
	isClient bool,
) *Conn {
	return &Conn{
		rAddr:                   rAddr,
		nextConn:                netctx.NewPacketConn(nextConn),
		handshakeConfig:         handshakeConfig,
		fragmentBuffer:          dtlsfragmentbuffer.New(),
		handshakeCache:          dtlsflight.NewCache(),
		maximumTransmissionUnit: configValues.maximumTransmissionUnit,
		paddingLengthGenerator:  configValues.paddingLengthGenerator,

		decrypted: make(chan any, 1),
		log:       configValues.logger,

		readDeadline:  deadline.New(),
		writeDeadline: deadline.New(),

		reading:               make(chan struct{}, 1),
		handshakeRecv:         make(chan dtlshandshake.RecvHandshakeState),
		handshakeEstablished:  dtlshandshake.NewEstablishment(),
		closed:                closer.NewCloser(),
		cancelHandshaker:      func() {},
		cancelHandshakeReader: func() {},

		replayProtectionWindow: uint(configValues.replayProtectionWindow), //nolint:gosec // G115

		state: dtlsstate.NewActive(isClient),
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
	c.handshakeConfig.LocalCipherSuites = filterCipherSuitesForVersion(
		c.handshakeConfig.LocalCipherSuites,
		common.LocalVersion,
	)
	if len(c.handshakeConfig.LocalCipherSuites) == 0 {
		return dtlserrors.ErrNoAvailableCipherSuites
	}

	if err := c.handshake(ctx, start); err != nil {
		if common.LocalVersion.Equal(protocol.Version1_2) && !c.isHandshakeCompletedSuccessfully() {
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
		return c.prepareHandshakeStart12(), nil
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

	return handshakeStart{
		flight12: dtlsflight12.Flight1,
		flight13: dtlsflight13.Flight1,
		fsmState: dtlshandshake.StateWaiting,
		flights:  initialFlights,
		postSetup: func(ctx context.Context) {
			c.primeHandshakeRecv(ctx)
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
		fsmState: dtlshandshake.StatePreparing,
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

// ServerWithOptions listens for incoming DTLS connections.
func ServerWithOptions(conn net.PacketConn, rAddr net.Addr, opts ...ServerOption) (*Conn, error) {
	config, err := buildServerConfig(opts...)
	if err != nil {
		return nil, err
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return serverWithConfig(conn, rAddr, config)
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

	ctx, cancel := c.contextWithClose(c.writeDeadline)
	defer cancel()

	err := c.writeApplicationData(ctx, []*dtlsflight.Packet{
		c.newApplicationDataPacket(payload),
	})
	if errors.Is(err, context.Canceled) && errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		return len(payload), dtlserrors.ErrDeadlineExceeded
	}

	return len(payload), err
}

func (c *Conn) newApplicationDataPacket(payload []byte) *dtlsflight.Packet {
	return &dtlsflight.Packet{
		Record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
			},
			Content: &protocol.ApplicationData{
				// The DTLS 1.3 FSM may retain this packet after Write returns on
				// cancellation, so take ownership before queueing it.
				Data: bytes.Clone(payload),
			},
		},
		ShouldWrapCID: c.state.ShouldWrapConnectionID(),
		ShouldEncrypt: true,
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
	if !dtlsstate.CommonState(c.state).LocalVersion.Equal(protocol.Version1_3) {
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

func (c *Conn) writeApplicationData(ctx context.Context, pkts []*dtlsflight.Packet) error {
	if dtlsstate.CommonState(c.state).LocalVersion.Equal(protocol.Version1_3) {
		writer, ok := c.fsm.(dtlshandshake.ApplicationDataWriter)
		if !ok {
			return dtlserrors.ErrNotImplemented
		}

		return writer.WriteApplicationData(ctx, pkts)
	}

	epoch := dtlsstate.CommonState(c.state).LocalEpoch()
	for _, pkt := range pkts {
		pkt.Record.Header.Epoch = epoch
	}
	_, err := c.writePacketsWithResult(ctx, pkts)

	return err
}

// Close closes the connection.
func (c *Conn) Close() error {
	err := c.close(true)
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

func (c *Conn) writePackets(ctx context.Context, pkts []*dtlsflight.Packet) error {
	_, err := c.writePacketsWithResult(ctx, pkts)

	return err
}

func (c *Conn) writePacketsWithResult(
	ctx context.Context,
	pkts []*dtlsflight.Packet,
) (*dtlshandshake.WriteResult, error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	return c.writePacketsWithResultLocked(ctx, pkts)
}

func (c *Conn) writePacketsWithResultLocked(
	ctx context.Context,
	pkts []*dtlsflight.Packet,
) (*dtlshandshake.WriteResult, error) {
	datagrams, rAddr, err := c.prepareRawPacketsTracked(pkts)
	if err != nil {
		return nil, err
	}

	result := &dtlshandshake.WriteResult{}
	for _, datagram := range datagrams {
		if _, err = c.nextConn.WriteToContext(ctx, datagram.raw, rAddr); err != nil {
			if errors.Is(err, context.Canceled) && c.isConnectionClosed() {
				return nil, ErrConnClosed
			}

			return nil, netError(err)
		}
		result.TrackedRecords = append(result.TrackedRecords, datagram.tracked...)
	}

	return result, nil
}

type preparedDatagram struct {
	raw     []byte
	tracked []dtlshandshake.SentHandshakeRecord
}

func (c *Conn) prepareRawPacketsTracked(pkts []*dtlsflight.Packet) ([]preparedDatagram, net.Addr, error) {
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

func (c *Conn) prepareRecordsTracked(pkts []*dtlsflight.Packet) ([]preparedRecord, error) {
	var records []preparedRecord
	for _, pkt := range pkts {
		prepared, err := c.prepareRecordsFromPacket(pkt)
		if err != nil {
			return nil, err
		}
		records = append(records, prepared...)
	}

	return records, nil
}

func (c *Conn) prepareRecordsFromPacket(pkt *dtlsflight.Packet) ([]preparedRecord, error) {
	handshakeRecord, ok := pkt.Record.Content.(*handshake.Handshake)
	if ok && dtlsstate.CommonState(c.state).LocalVersion.Equal(protocol.Version1_3) && pkt.ShouldEncrypt {
		if err := c.cacheHandshakePacket(pkt, handshakeRecord); err != nil {
			return nil, err
		}

		return c.processProtectedHandshakePacketTracked(pkt, handshakeRecord)
	}

	rawPackets, err := c.prepareRawPacket(pkt)
	if err != nil {
		return nil, err
	}
	records := make([]preparedRecord, 0, len(rawPackets))
	for _, raw := range rawPackets {
		records = append(records, preparedRecord{raw: raw})
	}

	return records, nil
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
		srvCliStr(dtlsstate.CommonState(c.state).IsClient), dtlsHandshake.Header.Type.String(),
		pkt.Record.Header.Epoch, dtlsHandshake.Header.MessageSequence)

	c.handshakeCache.Push(
		handshakeRaw[recordlayer.FixedHeaderSize:],
		pkt.Record.Header.Epoch,
		dtlsHandshake.Header.MessageSequence,
		dtlsHandshake.Header.Type,
		dtlsstate.CommonState(c.state).IsClient,
	)

	return nil
}

func (c *Conn) contextWithClose(ctx context.Context) (context.Context, context.CancelFunc) {
	closeCtx, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
	go func() {
		select {
		case <-c.closed.Done():
			cancel(context.Canceled)
		case <-ctx.Done():
			err := ctx.Err()
			if err == nil {
				err = context.DeadlineExceeded
			}
			cancel(err)
		case <-closeCtx.Done():
		}
	}()

	return closeCtx, func() {
		cancel(context.Canceled)
	}
}

func (c *Conn) contextWithCloseAndWriteDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	operationCtx, cancel := context.WithCancelCause(context.Background())
	go func() {
		select {
		case <-c.closed.Done():
			cancel(context.Canceled)
		case <-c.writeDeadline.Done():
			cancel(context.DeadlineExceeded)
		case <-ctx.Done():
			cancel(ctx.Err())
		case <-operationCtx.Done():
		}
	}()

	return operationCtx, func() {
		cancel(context.Canceled)
	}
}

func (c *Conn) compactPreparedRecords(records []preparedRecord) []preparedDatagram {
	datagrams := make([]preparedDatagram, 0, len(records))
	current := preparedDatagram{}
	for _, record := range records {
		if len(current.raw) > 0 && len(current.raw)+len(record.raw) >= c.maximumTransmissionUnit {
			datagrams = append(datagrams, current)
			current = preparedDatagram{}
		}
		current.raw = append(current.raw, record.raw...)
		if record.tracked != nil {
			current.tracked = append(current.tracked, *record.tracked)
		}
	}
	datagrams = append(datagrams, current)

	return datagrams
}

func (c *Conn) processPacket(pkt *dtlsflight.Packet) ([]byte, error) { //nolint:cyclop
	epoch := pkt.Record.Header.Epoch
	seq, err := c.nextLocalSequenceNumber(epoch)
	if err != nil {
		return nil, err
	}
	pkt.Record.Header.SequenceNumber = seq

	common := dtlsstate.CommonState(c.state)
	if common.LocalVersion.Equal(protocol.Version1_3) && pkt.ShouldEncrypt {
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
		rawInner, err := inner.Marshal()
		if err != nil {
			return nil, err
		}
		cidHeader := &recordlayer.Header{
			Version:        pkt.Record.Header.Version,
			ContentType:    protocol.ContentTypeConnectionID,
			Epoch:          pkt.Record.Header.Epoch,
			ContentLen:     uint16(len(rawInner)), //nolint:gosec //G115
			ConnectionID:   common.RemoteConnectionID,
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
		rawPacket, err = common.CipherSuite.Encrypt(pkt.Record, rawPacket)
		if err != nil {
			return nil, err
		}
	}

	return rawPacket, nil
}

func (c *Conn) nextLocalSequenceNumber(epoch uint16) (uint64, error) {
	common := dtlsstate.CommonState(c.state)
	for len(common.LocalSequenceNumber) <= int(epoch) {
		common.LocalSequenceNumber = append(common.LocalSequenceNumber, uint64(0))
	}
	seq := atomic.AddUint64(&common.LocalSequenceNumber[epoch], 1) - 1
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
	case *handshake.Handshake, *alert.Alert, *protocol.ApplicationData, *protocol.ACK:
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
	generation, err := c.writeTrafficGeneration(epoch)
	if err != nil {
		return nil, err
	}

	header := recordlayer.UnifiedHeader{
		EpochLow:       uint8(epoch & 0x3),
		SequenceNumber: uint16(seq & 0xffff),
		SeqBit:         true,
		LengthBit:      true,
	}
	if state13, ok := c.state.(*dtlsstate.State13); ok &&
		state13.CID.Negotiated && state13.CID.Send.UseCID {
		header.ConnectionID = bytes.Clone(state13.CID.Send.Active)
	}

	ciphertext, err := generation.Protection.Seal(
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

func (c *Conn) writeTrafficGeneration(epoch uint16) (*dtlsstate.TrafficGeneration, error) {
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

//nolint:cyclop
func (c *Conn) processHandshakePacket(pkt *dtlsflight.Packet, dtlsHandshake *handshake.Handshake) ([][]byte, error) {
	common := dtlsstate.CommonState(c.state)
	if common.LocalVersion.Equal(protocol.Version1_3) && pkt.ShouldEncrypt {
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
				ConnectionID:   common.RemoteConnectionID,
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
			rawPacket, err = common.CipherSuite.Encrypt(pkt.Record, rawPacket)
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
		// TODO: Replace this temporary error when CID protection is implemented.
		// nolint:godox
		return nil, dtlserrors.ErrInvalidPacket
	}
	if pkt.ShouldWrapCID {
		return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	prepared, err := c.processProtectedHandshakePacketTracked(pkt, dtlsHandshake)
	if err != nil {
		return nil, err
	}
	rawPackets := make([][]byte, 0, len(prepared))
	for _, record := range prepared {
		rawPackets = append(rawPackets, record.raw)
	}

	return rawPackets, nil
}

type preparedRecord struct {
	raw     []byte
	tracked *dtlshandshake.SentHandshakeRecord
}

func (c *Conn) processProtectedHandshakePacketTracked(
	pkt *dtlsflight.Packet,
	dtlsHandshake *handshake.Handshake,
) ([]preparedRecord, error) {
	if pkt.ShouldWrapCID {
		return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	handshakeFragments, err := c.fragmentHandshake(dtlsHandshake)
	if err != nil {
		return nil, err
	}

	rawPackets := make([]preparedRecord, 0, len(handshakeFragments))
	epoch := pkt.Record.Header.Epoch
	for _, handshakeFragment := range handshakeFragments {
		selected, err := selectHandshakeFragment(pkt.HandshakeFragmentOffsets, handshakeFragment)
		if err != nil {
			return nil, err
		}
		if !selected {
			continue
		}
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

		prepared := preparedRecord{raw: rawPacket}
		if pkt.ShouldTrackACK {
			fragmentHeader := &handshake.Header{}
			if err = fragmentHeader.Unmarshal(handshakeFragment); err != nil {
				return nil, err
			}
			prepared.tracked = &dtlshandshake.SentHandshakeRecord{
				Number: protocol.RecordNumber{Epoch: uint64(epoch), SequenceNumber: seq},
				Fragments: []dtlshandshake.SentHandshakeFragment{{
					MessageSequence: fragmentHeader.MessageSequence,
					Offset:          fragmentHeader.FragmentOffset,
					Length:          fragmentHeader.FragmentLength,
				}},
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

func (c *Conn) fragmentHandshake(dtlsHandshake *handshake.Handshake) ([][]byte, error) {
	content, err := dtlsHandshake.Message.Marshal()
	if err != nil {
		return nil, err
	}

	fragmentedHandshakes := make([][]byte, 0)

	contentFragments := util.SplitBytes(content, c.maximumTransmissionUnit)
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
			FragmentOffset:  uint32(offset),
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

func (c *Conn) readAndBuffer(ctx context.Context) error {
	summary, err := c.readAndProcessDatagram(ctx)
	if err != nil {
		return err
	}
	if !summary.containsHandshake && len(summary.receivedACKs) == 0 {
		return nil
	}

	s := dtlshandshake.RecvHandshakeState{
		Done:         make(chan struct{}),
		HasHandshake: summary.containsHandshake,
		IsRetransmit: summary.retransmit,
		ACKs:         summary.receivedACKs,
		RecordsToACK: c.takePendingACKs(),
	}
	select {
	case c.handshakeRecv <- s:
		// If the other party may retransmit the flight,
		// we should respond even if it not a new message.
		<-s.Done
	case <-c.fsm.Done():
	}

	return nil
}

func (c *Conn) readAndProcessDatagram(ctx context.Context) (datagramProcessingSummary, error) {
	bufptr, ok := poolReadBuffer.Get().(*[]byte)
	if !ok {
		return datagramProcessingSummary{}, dtlserrors.ErrFailedToAccessPoolReadBuffer
	}
	bufferLease := readBufferLease{conn: c, recyclableReadBuffer: bufptr}
	defer bufferLease.releaseReadBuffer()

	b := *bufptr
	i, rAddr, err := c.nextConn.ReadFromContext(ctx, b)
	if err != nil {
		return datagramProcessingSummary{}, netError(err)
	}

	pkts, err := c.unpackDatagram(b[:i])
	if err != nil {
		return datagramProcessingSummary{}, err
	}

	var summary datagramProcessingSummary
	for _, p := range pkts {
		outcome, err := c.processIncomingPacket(ctx, p, rAddr, &bufferLease)
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

func (c *Conn) takePendingACKs() []protocol.RecordNumber {
	c.lock.Lock()
	defer c.lock.Unlock()

	records := c.pendingACKs
	c.pendingACKs = nil

	return records
}

func (c *Conn) handleQueuedPackets(ctx context.Context) error {
	c.lock.Lock()
	pkts := c.encryptedPackets
	c.encryptedPackets = nil
	c.lock.Unlock()

	for _, p := range pkts {
		_, err := c.processIncomingPacket(ctx, p.data, p.rAddr, nil) // don't re-enqueue
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

	// Prevent an append by a queue consumer from overwriting an adjacent record
	// that shares the same datagram backing array.
	packet.data = packet.data[:len(packet.data):len(packet.data)]
	c.encryptedPackets = append(c.encryptedPackets, packet)

	return true
}

func (c *Conn) maxQueueableFutureEpoch(remoteEpoch uint16) uint16 {
	maxEpoch := remoteEpoch + 1
	if remoteEpoch >= dtlsflight13.EpochHandshake {
		return maxEpoch
	}
	if dtlsstate.CommonState(c.state).LocalVersion.Equal(protocol.Version1_3) {
		return dtlsflight13.EpochHandshake
	}
	if !dtlsstate.CommonState(c.state).LocalVersion.Equal(protocol.Version{}) {
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
	common := dtlsstate.CommonState(c.state)
	if common.LocalVersion.Equal(protocol.Version1_3) ||
		protocol.IsDTLS13Ciphertext(protocol.ContentType(buf[0])) {
		cidLength := len(common.LocalConnectionIDForInboundRecords())
		state13, is13 := c.state.(*dtlsstate.State13)

		return recordlayer.UnpackDatagram13(buf, cidLength, is13 && state13.CID.Negotiated, true)
	}

	return recordlayer.ContentAwareUnpackDatagram(buf, len(common.LocalConnectionIDForInboundRecords()))
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
	localCID := dtlsstate.CommonState(c.state).LocalConnectionIDForInboundRecords()
	cidExpected, cidAllowed, err := c.ciphertextCIDPolicy(localCID)
	if err != nil {
		return record, err
	}
	if hasCID {
		if !cidAllowed {
			return record, dtlserrors.ErrInvalidCiphertextHeader
		}
		record.Header.ConnectionID = make([]byte, len(localCID))
	}

	if err := record.Unmarshal(buf); err != nil {
		return record, err
	}
	if cidExpected && !hasCID {
		return record, dtlserrors.ErrInvalidCiphertextHeader
	}
	if hasCID {
		if !bytes.Equal(localCID, record.Header.ConnectionID) {
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

func (c *Conn) openCiphertextRecord(
	record recordlayer.CiphertextRecord13,
) (recordlayer.InnerPlaintext, uint64, uint16, error) {
	var candidateBuffer [4]*dtlsstate.TrafficGeneration
	candidates, remoteEpoch, err := c.readTrafficCandidates(record.Header.EpochLow, candidateBuffer[:0])
	if err != nil {
		return recordlayer.InnerPlaintext{}, 0, 0, err
	}

	var candidateErr error
	eligible := false
	for _, generation := range candidates {
		// Reject generations before it's authorized and
		// the receive epoch has advanced.
		if generation.Epoch > remoteEpoch {
			continue
		}
		eligible = true
		if generation.Protection == nil {
			continue
		}
		innerPlaintext, sequenceNumber, err := c.openCiphertextWithGeneration(record, generation)
		if err != nil {
			candidateErr = err

			continue
		}

		return innerPlaintext, sequenceNumber, generation.Epoch, nil
	}
	if !eligible {
		return recordlayer.InnerPlaintext{}, 0, 0, dtlserrors.ErrInvalidEpoch
	}
	if candidateErr == nil {
		candidateErr = dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	return recordlayer.InnerPlaintext{}, 0, 0, candidateErr
}

func (c *Conn) readTrafficCandidates(
	epochLow uint8,
	candidates []*dtlsstate.TrafficGeneration,
) ([]*dtlsstate.TrafficGeneration, uint16, error) {
	state13, ok := c.state.(*dtlsstate.State13)
	if !ok || state13.TrafficKeys == nil {
		return nil, 0, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}
	candidates = state13.TrafficKeys.ReadCandidates(epochLow, candidates)
	if len(candidates) == 0 {
		return nil, 0, dtlserrors.ErrInvalidEpoch
	}

	return candidates, state13.RemoteEpoch(), nil
}

func (c *Conn) openCiphertextWithGeneration(
	record recordlayer.CiphertextRecord13,
	generation *dtlsstate.TrafficGeneration,
) (recordlayer.InnerPlaintext, uint64, error) {
	clearHeader, err := generation.Protection.UnmaskSequenceNumber(record.Header, record.EncryptedRecord)
	if err != nil {
		return recordlayer.InnerPlaintext{}, 0, err
	}
	sequenceNumber := reconstructSequenceNumber(
		clearHeader.SequenceNumber,
		clearHeader.SeqBit,
		c.highestRemoteSequenceNumber(generation.Epoch),
	)
	innerPlaintext, err := generation.Protection.Open(
		record.Header,
		sequenceNumber,
		record.EncryptedRecord,
	)
	if err != nil {
		return recordlayer.InnerPlaintext{}, 0, err
	}

	switch innerPlaintext.RealType {
	case protocol.ContentTypeAlert,
		protocol.ContentTypeHandshake,
		protocol.ContentTypeApplicationData,
		protocol.ContentTypeACK:
		return innerPlaintext, sequenceNumber, nil
	default:
		return recordlayer.InnerPlaintext{}, 0, dtlserrors.ErrInvalidContentType
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

func (c *Conn) highestRemoteSequenceNumber(epoch uint16) uint64 {
	common := dtlsstate.CommonState(c.state)
	if int(epoch) >= len(common.RemoteSequenceNumber) {
		return 0
	}

	return atomic.LoadUint64(&common.RemoteSequenceNumber[epoch])
}

func (c *Conn) updateRemoteSequenceNumber(epoch uint16, sequenceNumber uint64) {
	common := dtlsstate.CommonState(c.state)
	for len(common.RemoteSequenceNumber) <= int(epoch) {
		common.RemoteSequenceNumber = append(common.RemoteSequenceNumber, 0)
	}
	for {
		highest := atomic.LoadUint64(&common.RemoteSequenceNumber[epoch])
		if sequenceNumber <= highest {
			return
		}
		if atomic.CompareAndSwapUint64(&common.RemoteSequenceNumber[epoch], highest, sequenceNumber) {
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
	bufferLease *readBufferLease,
) (incomingPacketState, bool) {
	if protocol.IsDTLS13Ciphertext(protocol.ContentType(buf[0])) {
		return c.prepareCiphertextPacket(buf, rAddr, bufferLease)
	}

	return c.prepareLegacyPacket(buf, rAddr, bufferLease)
}

func (c *Conn) prepareCiphertextPacket(
	buf []byte,
	rAddr net.Addr,
	bufferLease *readBufferLease,
) (incomingPacketState, bool) {
	ciphertext, err := c.unmarshalCiphertextRecord(buf)
	if err != nil {
		c.log.Debugf("discarded broken ciphertext packet: %v", err)

		return incomingPacketState{}, false
	}

	if c.queueIfCipherSuiteUninitialized(
		rAddr,
		buf,
		bufferLease,
		"handshake not finished, queuing ciphertext packet",
	) {
		return incomingPacketState{}, false
	}

	innerPlaintext, sequenceNumber, epoch, err := c.openCiphertextRecord(ciphertext)
	if err != nil {
		if errors.Is(err, dtlserrors.ErrInvalidEpoch) {
			c.handleFutureCiphertextPacket(
				ciphertext.Header.EpochLow,
				dtlsstate.CommonState(c.state).RemoteEpoch(),
				rAddr,
				buf,
				bufferLease,
			)
		}
		c.log.Debugf("%s: decrypt failed: %s", srvCliStr(dtlsstate.CommonState(c.state).IsClient), err)

		return incomingPacketState{}, false
	}

	markPacketAsValid, ok := c.protectedReplayMarker(epoch, sequenceNumber)
	if !ok {
		return incomingPacketState{}, false
	}

	return c.prepareInnerPlaintextRecord(epoch, sequenceNumber, innerPlaintext, markPacketAsValid)
}

func (c *Conn) prepareInnerPlaintextRecord(
	remoteEpoch uint16,
	sequenceNumber uint64,
	innerPlaintext recordlayer.InnerPlaintext,
	markPacketAsValid func() bool,
) (incomingPacketState, bool) {
	switch innerPlaintext.RealType {
	case protocol.ContentTypeHandshake, protocol.ContentTypeAlert,
		protocol.ContentTypeApplicationData, protocol.ContentTypeACK:
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
	bufferLease *readBufferLease,
) {
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

func (c *Conn) protectedReplayMarker(epoch uint16, sequenceNumber uint64) (func() bool, bool) {
	common := dtlsstate.CommonState(c.state)
	for len(common.ReplayDetector) <= int(epoch) {
		common.ReplayDetector = append(common.ReplayDetector,
			replaydetector.New(c.replayProtectionWindow, ^uint64(0)),
		)
	}
	accept, ok := common.ReplayDetector[int(epoch)].Check(sequenceNumber)
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
	bufferLease *readBufferLease,
	message string,
) bool {
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
	if state13, ok := c.state.(*dtlsstate.State13); ok && common.LocalVersion.Equal(protocol.Version1_3) {
		if state13.TrafficKeys == nil {
			return false
		}
		generation, found := state13.TrafficKeys.Read(common.RemoteEpoch())

		return found && generation.Protection != nil
	}

	return common.CipherSuite != nil && common.CipherSuite.IsInitialized()
}

func (c *Conn) prepareLegacyPacket(
	buf []byte,
	rAddr net.Addr,
	bufferLease *readBufferLease,
) (incomingPacketState, bool) {
	header, ok := c.unmarshalLegacyHeader(buf)
	if !ok {
		return incomingPacketState{}, false
	}
	if c.handleFutureLegacyPacket(header, rAddr, buf, bufferLease) {
		return incomingPacketState{}, false
	}

	markPacketAsValid, ok := c.legacyReplayMarker(header)
	if !ok {
		return incomingPacketState{}, false
	}

	originalCID := false
	if header.Epoch != 0 {
		var decryptOK bool
		buf, originalCID, decryptOK = c.decryptLegacyPacket(header, buf, rAddr, bufferLease)
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
	localCID := dtlsstate.CommonState(c.state).LocalConnectionIDForInboundRecords()
	if len(localCID) > 0 {
		header.ConnectionID = make([]byte, len(localCID))
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
	bufferLease *readBufferLease,
) bool {
	remoteEpoch := dtlsstate.CommonState(c.state).RemoteEpoch()
	if header.Epoch <= remoteEpoch {
		return false
	}
	if header.Epoch > c.maxQueueableFutureEpoch(remoteEpoch) {
		c.log.Debugf("discarded future packet (epoch: %d, seq: %d)",
			header.Epoch, header.SequenceNumber,
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

func (c *Conn) legacyReplayMarker(header *recordlayer.Header) (func() bool, bool) {
	common := dtlsstate.CommonState(c.state)
	for len(common.ReplayDetector) <= int(header.Epoch) {
		common.ReplayDetector = append(common.ReplayDetector,
			replaydetector.New(c.replayProtectionWindow, recordlayer.MaxSequenceNumber),
		)
	}
	markPacketAsValid, ok := common.ReplayDetector[int(header.Epoch)].Check(header.SequenceNumber)
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
	bufferLease *readBufferLease,
) ([]byte, bool, bool) {
	if c.queueIfCipherSuiteUninitialized(
		rAddr,
		buf,
		bufferLease,
		"handshake not finished, queuing packet",
	) {
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
	common := dtlsstate.CommonState(c.state)
	if len(common.LocalConnectionIDForInboundRecords()) == 0 || header.ContentType == protocol.ContentTypeConnectionID {
		return true
	}

	c.log.Debug("discarded packet missing connection ID after value negotiated")

	return false
}

func (c *Conn) decryptLegacyRecord(header *recordlayer.Header, buf []byte) ([]byte, bool) {
	var decryptHeader recordlayer.Header
	common := dtlsstate.CommonState(c.state)
	if header.ContentType == protocol.ContentTypeConnectionID {
		decryptHeader.ConnectionID = make([]byte, len(common.LocalConnectionIDForInboundRecords()))
	}
	decrypted, err := common.CipherSuite.Decrypt(decryptHeader, buf)
	if err != nil {
		c.log.Debugf("%s: decrypt failed: %s", srvCliStr(common.IsClient), err)

		return nil, false
	}

	return decrypted, true
}

func (c *Conn) validateLegacyCID(header *recordlayer.Header) bool {
	if bytes.Equal(dtlsstate.CommonState(c.state).LocalConnectionIDForInboundRecords(), header.ConnectionID) {
		return true
	}

	c.log.Debug("unexpected connection ID")

	return false
}

func (c *Conn) unpackLegacyCIDPacket(header *recordlayer.Header, buf []byte) ([]byte, bool) {
	ip := &recordlayer.InnerPlaintext{}
	if err := ip.Unmarshal(buf[header.Size():]); err != nil {
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

func (c *Conn) bufferHandshakeRecord(
	buf []byte,
	header *recordlayer.Header,
	markPacketAsValid func() bool,
) (packetOutcome, bool) {
	c.syncFragmentBufferHandshakeSequence()
	isHandshake, isRetransmit, err := c.fragmentBuffer.Push(bytes.Clone(buf))
	if err != nil {
		// Decode error must be silently discarded
		// [RFC6347 Section-4.1.2.7]
		c.log.Debugf("defragment failed: %s", err)

		return packetOutcome{}, true
	}
	if !isHandshake {
		return packetOutcome{}, false
	}

	markPacketAsValid()
	if dtlsstate.CommonState(c.state).LocalVersion.Equal(protocol.Version1_3) &&
		header.Epoch >= dtlsflight13.EpochHandshake {
		c.lock.Lock()
		c.pendingACKs = append(c.pendingACKs, protocol.RecordNumber{
			Epoch: uint64(header.Epoch), SequenceNumber: header.SequenceNumber,
		})
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

	return packetOutcome{containsHandshake: true, retransmit: isRetransmit}, true
}

func (c *Conn) handleChangeCipherSpecRecord(
	prepared incomingPacketState,
	rAddr net.Addr,
	bufferLease *readBufferLease,
) bool {
	common := dtlsstate.CommonState(c.state)
	if !c.hasInboundRecordProtection() {
		if bufferLease != nil {
			if ok := bufferLease.enqueue(addrPkt{rAddr: rAddr, data: prepared.buf}); ok {
				c.log.Debugf("CipherSuite not initialized, queuing packet")
			}
		}

		return false
	}

	newRemoteEpoch := prepared.header.Epoch + 1
	c.log.Tracef("%s: <- ChangeCipherSpec (epoch: %d)", srvCliStr(common.IsClient), newRemoteEpoch)
	if common.RemoteEpoch()+1 != newRemoteEpoch {
		return false
	}

	c.setRemoteEpoch(newRemoteEpoch)

	return prepared.markPacketAsValid()
}

func (c *Conn) handleApplicationDataRecord(
	ctx context.Context,
	content *protocol.ApplicationData,
	prepared incomingPacketState,
) (bool, packetOutcome, error) {
	if prepared.header.Epoch == 0 {
		return false, packetOutcome{
			responseAlert: &alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage},
		}, dtlserrors.ErrApplicationDataEpochZero
	}

	isLatestSeqNum := prepared.markPacketAsValid()
	select {
	case c.decrypted <- content.Data:
	case <-c.closed.Done():
	case <-ctx.Done():
	}

	return isLatestSeqNum, packetOutcome{}, nil
}

func (c *Conn) handleRecordContent(
	ctx context.Context,
	content protocol.Content,
	prepared incomingPacketState,
	rAddr net.Addr,
	bufferLease *readBufferLease,
) (bool, packetOutcome, error) {
	switch content := content.(type) {
	case *protocol.ACK:
		prepared.markPacketAsValid()

		return false, packetOutcome{
			receivedACK: &protocol.ACK{Records: append([]protocol.RecordNumber(nil), content.Records...)},
		}, nil
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
	default:
		return false, packetOutcome{
			responseAlert: &alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage},
		}, fmt.Errorf("%w: %d", dtlserrors.ErrUnhandledContextType, content.ContentType())
	}
}

func (c *Conn) handleIncomingPacket(
	ctx context.Context,
	buf []byte,
	rAddr net.Addr,
	bufferLease *readBufferLease,
) (packetOutcome, error) {
	if len(buf) == 0 {
		return packetOutcome{}, nil
	}

	prepared, ok := c.prepareIncomingPacket(buf, rAddr, bufferLease)
	if !ok {
		return packetOutcome{}, nil
	}
	if outcome, handled := c.bufferHandshakeRecord(
		prepared.buf,
		prepared.header,
		prepared.markPacketAsValid,
	); handled {
		return outcome, nil
	}

	r := &recordlayer.RecordLayer{}
	if err := r.Unmarshal(prepared.buf); err != nil {
		return packetOutcome{
			responseAlert: &alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
		}, err
	}

	isLatestSeqNum, outcome, err := c.handleRecordContent(ctx, r.Content, prepared, rAddr, bufferLease)
	if err != nil || outcome.responseAlert != nil {
		return outcome, err
	}

	// Any valid connection ID record is a candidate for updating the remote
	// address if it is the latest record received.
	// https://datatracker.ietf.org/doc/html/rfc9146#peer-address-update
	if prepared.originalCID && isLatestSeqNum && rAddr != c.RemoteAddr() {
		c.lock.Lock()
		c.rAddr = rAddr
		c.lock.Unlock()
	}

	return outcome, nil
}

func (c *Conn) processIncomingPacket(
	ctx context.Context,
	buf []byte,
	rAddr net.Addr,
	bufferLease *readBufferLease,
) (packetOutcome, error) {
	outcome, err := c.handleIncomingPacket(ctx, buf, rAddr, bufferLease)
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
	return c.handshakeRecv
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

	return c.writePackets(ctx, []*dtlsflight.Packet{
		{
			Record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Epoch:   common.LocalEpoch(),
					Version: protocol.Version1_2,
				},
				Content: &alert.Alert{
					Level:       level,
					Description: desc,
				},
			},
			ShouldWrapCID: c.state.ShouldWrapConnectionID(),
			ShouldEncrypt: c.isHandshakeCompletedSuccessfully(),
		},
	})
}

func (c *Conn) isHandshakeCompletedSuccessfully() bool {
	return c.handshakeEstablished.Established()
}

func (c *Conn) negotiateVersionServer(ctx context.Context) error {
	for {
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
func (c *Conn) negotiateVersionClient(ctx context.Context) ([]*dtlsflight.Packet, error) {
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
	if err := c.writePackets(ctx, pkts); err != nil {
		return nil, err
	}

	for {
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
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: c.handshakeConfig.InitialEpoch, IsClient: true, Optional: false}, //nolint:lll
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
		return false, fmt.Errorf(
			"%w: %w",
			dtlserrors.ErrNoCommonProtocolVersion,
			&alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
		)
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
	if err := extensionnegotiation.ValidateServerHelloResponse(
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

func remoteVersionsFromHelloRetryRequest(
	remote []protocol.Version,
	seenSupportedVersions bool,
	err error,
) ([]protocol.Version, error) {
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %w",
			dtlserrors.ErrInvalidHelloRetryRequest,
			&alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
		)
	}
	if !seenSupportedVersions {
		return nil, fmt.Errorf(
			"%w: %w",
			dtlserrors.ErrInvalidHelloRetryRequest,
			&alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension},
		)
	}
	if !remote[0].Equal(protocol.Version1_3) {
		return nil, fmt.Errorf(
			"%w: %w",
			dtlserrors.ErrUnsupportedProtocolVersion,
			&alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
		)
	}

	return remote, nil
}

func (c *Conn) selectRemoteVersion(remote []protocol.Version) error {
	chosen, ok := dtlsconfig.SelectVersion(remote, c.handshakeConfig.MinVersion, c.handshakeConfig.MaxVersion)
	if !ok {
		return fmt.Errorf(
			"%w: %w",
			dtlserrors.ErrNoCommonProtocolVersion,
			&alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
		)
	}
	c.setNegotiatedVersion(remote, chosen)

	return nil
}

func (c *Conn) setNegotiatedVersion(remote []protocol.Version, chosen protocol.Version) {
	common := dtlsstate.CommonState(c.state)
	common.RemoteVersions = remote
	common.LocalVersion = chosen
	if chosen.Equal(protocol.Version1_3) {
		c.state = dtlsstate.Activate13(c.state)

		return
	}

	c.state = dtlsstate.Activate12(c.state)
}

// stampHandshakeSequence assigns the DTLS message_sequence to each handshake
// record in pkts. This is the subset of handshakeFSM.prepare()'s bookkeeping
// that generated dual-stack packets need before being passed to writePackets.
func (c *Conn) stampHandshakeSequence(pkts []*dtlsflight.Packet) {
	epoch := c.handshakeConfig.InitialEpoch
	for _, p := range pkts {
		p.Record.Header.Epoch += epoch
		if h, ok := p.Record.Content.(*handshake.Handshake); ok {
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
				continue
			}
			if action == readLoopDeliverAndContinue {
				c.deliverReadError(ctxRead, err)

				continue
			}

			select {
			case firstErr <- err:
			default:
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
	fsm, err := dtlshandshake.NewFSM13(
		state13,
		c.handshakeCache,
		c.handshakeConfig,
		start.flight13,
		start.flights,
		c.handshakeEstablished,
	)
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
	c.fsm = dtlshandshake.NewFSM12(
		state12,
		c.handshakeCache,
		c.handshakeConfig,
		start.flight12,
		start.flights,
		c.handshakeEstablished,
	)

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
	dtlsstate.CommonState(c.state).SetLocalEpoch(epoch)
}

func (c *Conn) setRemoteEpoch(epoch uint16) {
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
	localEpoch uint16,
) error {
	if current == nil || next == nil {
		return dtlserrors.ErrInvalidEpoch
	}
	if current.Epoch == ^uint16(0) {
		return dtlserrors.ErrEpochOverflow
	}
	if current.Epoch != localEpoch || next.Epoch != current.Epoch+1 || next.Generation != current.Generation+1 {
		return dtlserrors.ErrInvalidEpoch
	}

	return nil
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
