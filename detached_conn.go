// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

// DetachedEventKind identifies an event produced by a DetachedConn.
type DetachedEventKind uint8

const (
	// DetachedNoEvent indicates that no event is available.
	DetachedNoEvent DetachedEventKind = iota
	// DetachedWriteDatagrams provides one complete DTLS output batch in
	// Datagrams and its destination in Addr.
	DetachedWriteDatagrams
	// DetachedApplicationData provides plaintext received from the peer in Data.
	DetachedApplicationData
	// DetachedHandshakeDone indicates that the handshake has completed.
	DetachedHandshakeDone
	// DetachedClosed indicates that the connection has terminated with Err.
	DetachedClosed
)

// DetachedEvent is an event produced by a DetachedConn. Fields are populated
// according to Kind. Its byte slices are owned by the caller.
type DetachedEvent struct {
	Kind DetachedEventKind

	Datagrams [][]byte
	Data      []byte
	Addr      net.Addr
	Err       error
}

// DetachedConn is a DTLS connection whose datagram transport is supplied by
// its caller. It remains active for application and post-handshake traffic.
// This API is inspired by crypto/tls.QUICConn, Start, HandleDatagram, Write, and Close must not be
// called concurrently with one another. EventReady may be selected concurrently.
// After a driving method returns, call NextEvent until it returns DetachedNoEvent.
type DetachedConn struct {
	conn    *Conn
	inbound chan addrPkt
	driveMu sync.Mutex

	eventMu    sync.Mutex
	events     []DetachedEvent
	nextEvent  int
	eventReady chan struct{}

	started bool
	blocked chan struct{}

	established   atomic.Bool
	quiescentSkip atomic.Bool

	terminalOnce sync.Once
	terminal     chan struct{}
	terminalErr  error
}

var (
	errDetachedConnStarted = errors.New("DetachedConn.Start called more than once")
	errNilContext          = errors.New("nil context")
)

// DetachedClient returns a new detached client connection. Call Start before
// supplying datagrams.
func DetachedClient(remoteAddr net.Addr, opts ...ClientOption) (*DetachedConn, error) {
	if remoteAddr == nil {
		return nil, dtlserrors.ErrNilRemoteAddr
	}
	config, err := buildClientConfig(opts...)
	if err != nil {
		return nil, err
	}
	if config.psk != nil && config.PSKIdentityHint == nil {
		return nil, dtlserrors.ErrPSKAndIdentityMustBeSetForClient
	}
	if err = validateConfig(config); err != nil {
		return nil, err
	}

	return newDetachedConn(remoteAddr, config, true)
}

// DetachedServer returns a new detached server connection. Call Start before
// supplying datagrams.
func DetachedServer(remoteAddr net.Addr, opts ...ServerOption) (*DetachedConn, error) {
	if remoteAddr == nil {
		return nil, dtlserrors.ErrNilRemoteAddr
	}
	config, err := buildServerConfig(opts...)
	if err != nil {
		return nil, err
	}
	if err = validateConfig(config); err != nil {
		return nil, err
	}
	if config.OnConnectionAttempt != nil {
		if err = config.OnConnectionAttempt(remoteAddr); err != nil {
			return nil, err
		}
	}

	return newDetachedConn(remoteAddr, config, false)
}

func newDetachedConn(remoteAddr net.Addr, config *dtlsConfig, isClient bool) (*DetachedConn, error) {
	configValues, err := newConnConfigValues(config)
	if err != nil {
		return nil, err
	}

	detached := &DetachedConn{
		blocked:    make(chan struct{}),
		eventReady: make(chan struct{}, 1),
		inbound:    make(chan addrPkt),
		terminal:   make(chan struct{}),
	}
	handshakeConfig := newHandshakeConfig(config, configValues, nil)
	detached.conn = newConn(nil, remoteAddr, configValues, handshakeConfig, isClient)
	detached.conn.detached = detached
	detached.conn.handshakeConfig.TimerFactory = detached.newTimer
	detached.conn.setRemoteEpoch(0)
	detached.conn.setLocalEpoch(0)

	return detached, nil
}

// Start starts the handshake and runs it until it needs peer input. It may
// produce events and must be called at most once.
func (c *DetachedConn) Start(ctx context.Context) error {
	if ctx == nil {
		return errNilContext
	}
	c.driveMu.Lock()
	defer c.driveMu.Unlock()

	if c.started {
		return errDetachedConnStarted
	}
	c.started = true

	go func() {
		if err := c.conn.HandshakeContext(ctx); err != nil {
			c.terminate(err, true) //nolint:contextcheck
		}
	}()

	return c.waitUntilBlocked()
}

// HandleDatagram supplies one datagram received from addr and runs DTLS until
// it is blocked again. It may produce events. A nil addr uses the connection's
// current remote address. It does not retain datagram after returning.
func (c *DetachedConn) HandleDatagram(datagram []byte, addr net.Addr) error {
	c.driveMu.Lock()
	defer c.driveMu.Unlock()

	if !c.started {
		return dtlserrors.ErrHandshakeInProgress
	}
	if err := c.currentError(); err != nil {
		return err
	}
	if addr == nil {
		addr = c.conn.RemoteAddr()
	}

	select {
	case c.inbound <- addrPkt{rAddr: addr, data: datagram}:
	case <-c.terminal:
		return c.terminalErr
	}

	return c.waitUntilBlocked()
}

// Write encrypts plaintext application data and may produce events. The
// handshake must be complete.
func (c *DetachedConn) Write(data []byte) (int, error) {
	c.driveMu.Lock()
	defer c.driveMu.Unlock()

	if err := c.currentError(); err != nil {
		return 0, err
	}
	if !c.established.Load() {
		return 0, dtlserrors.ErrHandshakeInProgress
	}

	version := dtlsstate.CommonState(c.conn.state).LocalVersion
	err := c.conn.writeApplicationData(context.Background(), []*dtlsflight.Outbound{{
		Content:    &protocol.ApplicationData{Data: data},
		Protection: dtlsflight.ProtectionCiphertext,
	}})
	n := 0
	if err == nil {
		n = len(data)
	}
	if version == protocol.Version1_3 {
		if quiescentErr := c.waitUntilBlocked(); err == nil {
			err = quiescentErr
		}
	}

	return n, err
}

// EventReady is signaled when NextEvent may return an event and may be selected
// alongside transport input. Signals are coalesced
// It's the caller's responsibility to drain NextEvent until it returns DetachedNoEvent.
func (c *DetachedConn) EventReady() <-chan struct{} { return c.eventReady }

// NextEvent returns the next pending event, or DetachedNoEvent when the queue
// is empty.
func (c *DetachedConn) NextEvent() DetachedEvent {
	c.eventMu.Lock()
	defer c.eventMu.Unlock()

	if c.nextEvent == len(c.events) {
		c.events = c.events[:0]
		c.nextEvent = 0
		select {
		case <-c.eventReady:
		default:
		}

		return DetachedEvent{Kind: DetachedNoEvent}
	}
	event := c.events[c.nextEvent]
	c.events[c.nextEvent] = DetachedEvent{}
	c.nextEvent++

	return event
}

// ConnectionState returns the current DTLS connection state.
func (c *DetachedConn) ConnectionState() (State, bool) { return c.conn.ConnectionState() }

// SelectedSRTPProtectionProfile returns the negotiated SRTP profile.
func (c *DetachedConn) SelectedSRTPProtectionProfile() (SRTPProtectionProfile, bool) {
	return c.conn.SelectedSRTPProtectionProfile()
}

// RemoteSRTPMasterKeyIdentifier returns the peer's negotiated SRTP MKI.
func (c *DetachedConn) RemoteSRTPMasterKeyIdentifier() ([]byte, bool) {
	return c.conn.RemoteSRTPMasterKeyIdentifier()
}

// Close closes the detached connection.
func (c *DetachedConn) Close() error {
	c.driveMu.Lock()
	defer c.driveMu.Unlock()

	return c.conn.Close()
}

func (c *DetachedConn) publishDatagrams(datagrams [][]byte, addr net.Addr) {
	c.publishEvent(DetachedEvent{Kind: DetachedWriteDatagrams, Datagrams: datagrams, Addr: addr})
}

func (c *DetachedConn) publishApplicationData(data []byte) {
	c.publishEvent(DetachedEvent{Kind: DetachedApplicationData, Data: data})
}

func (c *DetachedConn) publishEvent(event DetachedEvent) {
	c.eventMu.Lock()
	c.events = append(c.events, event)
	select {
	case c.eventReady <- struct{}{}:
	default:
	}
	c.eventMu.Unlock()
}

func (c *DetachedConn) markQuiescent() {
	if c.conn.isHandshakeCompletedSuccessfully() && c.established.CompareAndSwap(false, true) {
		c.publishEvent(DetachedEvent{Kind: DetachedHandshakeDone})
	}

	select {
	case c.blocked <- struct{}{}:
	case <-c.terminal:
	}
}

func (c *DetachedConn) waitUntilBlocked() error {
	select {
	case <-c.blocked:
		return c.currentError()
	case <-c.terminal:
		return c.terminalErr
	}
}

func (c *DetachedConn) connectionTerminated(err error) {
	var receivedAlert *alertError
	if errors.As(err, &receivedAlert) && receivedAlert.Description == alert.CloseNotify {
		err = ErrConnClosed
	}
	c.terminate(err, false)
}

func (c *DetachedConn) terminate(err error, closeConn bool) {
	if err == nil {
		err = ErrConnClosed
	}
	c.terminalOnce.Do(func() {
		c.terminalErr = err
		if closeConn {
			_ = c.conn.close(false) //nolint:contextcheck
		}
		c.publishEvent(DetachedEvent{Kind: DetachedClosed, Err: err})
		close(c.terminal)
	})
}

func (c *DetachedConn) currentError() error {
	select {
	case <-c.terminal:
		return c.terminalErr
	default:
		return nil
	}
}

func (c *DetachedConn) readDatagram(ctx context.Context, buffer []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.inbound:
		return copy(buffer, packet.data), packet.rAddr, nil
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case <-c.terminal:
		return 0, nil, c.terminalErr
	}
}

func (c *DetachedConn) newTimer(d time.Duration) dtlsconfig.Timer {
	timer := &detachedTimer{owner: c, ch: make(chan time.Time, 1)}
	timer.timer = time.AfterFunc(d, timer.fire)

	return timer
}

type detachedTimer struct {
	owner   *DetachedConn
	ch      chan time.Time
	timer   *time.Timer
	claimed atomic.Bool
}

func (t *detachedTimer) C() <-chan time.Time { return t.ch }

func (t *detachedTimer) fire() {
	t.owner.driveMu.Lock()
	defer t.owner.driveMu.Unlock()
	if !t.claimed.CompareAndSwap(false, true) {
		return
	}

	t.ch <- time.Now()
	_ = t.owner.waitUntilBlocked()
}

func (t *detachedTimer) Stop() {
	if t.claimed.CompareAndSwap(false, true) {
		t.timer.Stop()
	}
}
