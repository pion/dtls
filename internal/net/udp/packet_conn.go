// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package udp implements DTLS specific UDP networking primitives.
// NOTE: this package is an adaptation of pion/transport/udp that allows for
// routing datagrams based on identifiers other than the remote address. The
// primary use case for this functionality is routing based on DTLS connection
// IDs. In order to allow for consumers of this package to treat connections as
// generic net.PacketConn, routing and identifier establishment is based on
// custom introspection of datagrams, rather than direct intervention by
// consumers. If possible, the updates made in this repository will be reflected
// back upstream. If not, it is likely that this will be moved to a public
// package in this repository.
//
// This package was migrated from pion/transport/udp at
// https://github.com/pion/transport/commit/6890c795c807a617c054149eee40a69d7fdfbfdb
package udp

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	idtlsnet "github.com/pion/dtls/v3/internal/net"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v4/deadline"
)

const (
	defaultReceiveBufferSize = 8192
	defaultListenBacklog     = 128 // same as Linux default
)

// Typed errors.
var (
	ErrClosedListener      = dtlserrors.ErrUDPClosedListener
	ErrListenQueueExceeded = dtlserrors.ErrUDPListenQueueExceeded
)

// listener augments a connection-oriented Listener over a UDP PacketConn.
type listener struct {
	pConn net.PacketConn

	accepting         atomic.Value // bool
	acceptCh          chan *PacketConn
	doneCh            chan struct{}
	doneOnce          sync.Once
	acceptFilter      func([]byte) bool
	datagramRouter    func([]byte) (string, bool)
	connIdentifier    func([]byte) (string, bool)
	receiveBufferSize int
	backlog           int

	conns  sync.Map // map[string]*PacketConn
	nConns atomic.Int64
	connWG sync.WaitGroup

	readWG   sync.WaitGroup
	errClose atomic.Value // error

	readDoneCh chan struct{}
	errRead    atomic.Value // error
}

// Accept waits for and returns the next connection to the listener.
func (l *listener) Accept() (net.PacketConn, net.Addr, error) {
	select {
	case c := <-l.acceptCh:
		l.connWG.Add(1)

		return c, c.raddr.Load().(net.Addr), nil //nolint:forcetypeassert

	case <-l.readDoneCh:
		err, _ := l.errRead.Load().(error)

		return nil, nil, err

	case <-l.doneCh:
		return nil, nil, ErrClosedListener
	}
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *listener) Close() error {
	var err error
	l.doneOnce.Do(func() {
		l.accepting.Store(false)
		close(l.doneCh)

		// Close unaccepted connections
		for {
			select {
			case c := <-l.acceptCh:
				c.closeAccess.Lock()
				if !c.closing.Swap(true) {
					c.listener.nConns.Add(-1)
					close(c.doneCh)
					// If we have an alternate identifier, remove it from the connection
					// map.
					if id := c.id.Load(); id != nil {
						l.conns.Delete(id.(string)) //nolint:forcetypeassert
					}
					l.conns.Delete(c.raddr.Load().(net.Addr).String()) //nolint:forcetypeassert
				}
				c.closeAccess.Unlock()

				continue
			default:
			}

			break
		}

		nConns := l.nConns.Load()

		l.connWG.Done()

		if nConns == 0 {
			// Wait if this is the final connection.
			l.readWG.Wait()
			if errClose, ok := l.errClose.Load().(error); ok {
				err = errClose
			}
		} else {
			err = nil
		}
	})

	return err
}

// Addr returns the listener's network address.
func (l *listener) Addr() net.Addr {
	return l.pConn.LocalAddr()
}

// ListenerOption configures a packet listener.
type ListenerOption func(*listener)

// WithBacklog sets the maximum number of pending connections.
func WithBacklog(backlog int) ListenerOption {
	return func(l *listener) {
		if backlog != 0 {
			l.backlog = backlog
		}
	}
}

// WithAcceptFilter sets the filter used to admit new connections.
func WithAcceptFilter(filter func([]byte) bool) ListenerOption {
	return func(l *listener) {
		l.acceptFilter = filter
	}
}

// WithDatagramRouter sets the function used to route incoming datagrams.
func WithDatagramRouter(router func([]byte) (string, bool)) ListenerOption {
	return func(l *listener) {
		l.datagramRouter = router
	}
}

// WithConnectionIdentifier sets the function used to identify outgoing datagrams.
func WithConnectionIdentifier(identifier func([]byte) (string, bool)) ListenerOption {
	return func(l *listener) {
		l.connIdentifier = identifier
	}
}

// WithReceiveBufferSize sets the size of the buffer used to read incoming datagrams.
func WithReceiveBufferSize(size int) ListenerOption {
	return func(l *listener) {
		if size > 0 {
			l.receiveBufferSize = size
		}
	}
}

// Listen creates a new listener over conn.
func Listen(conn net.PacketConn, opts ...ListenerOption) dtlsnet.PacketListener {
	packetListener := &listener{
		pConn:             conn,
		backlog:           defaultListenBacklog,
		receiveBufferSize: defaultReceiveBufferSize,
		doneCh:            make(chan struct{}),
		readDoneCh:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(packetListener)
	}

	packetListener.acceptCh = make(chan *PacketConn, packetListener.backlog)

	packetListener.accepting.Store(true)
	packetListener.connWG.Add(1)
	packetListener.readWG.Add(2) // wait readLoop and Close execution routine

	go packetListener.readLoop()
	go func() {
		packetListener.connWG.Wait()
		if err := packetListener.pConn.Close(); err != nil {
			packetListener.errClose.Store(err)
		}
		packetListener.readWG.Done()
	}()

	return packetListener
}

// readLoop dispatches packets to the proper connection, creating a new one if
// necessary, until all connections are closed.
func (l *listener) readLoop() {
	defer l.readWG.Done()
	defer close(l.readDoneCh)

	buf := make([]byte, l.receiveBufferSize)

	for {
		n, raddr, err := l.pConn.ReadFrom(buf)
		if err != nil {
			l.errRead.Store(err)

			return
		}
		conn, ok, err := l.getConn(raddr, buf[:n])
		if err != nil {
			continue
		}
		if ok {
			_, _ = conn.buffer.WriteTo(buf[:n], raddr)
		}
	}
}

// getConn gets an existing connection or creates a new one.
func (l *listener) getConn(raddr net.Addr, buf []byte) (*PacketConn, bool, error) { //nolint:cyclop
	// If we have a custom resolver, use it.
	if l.datagramRouter != nil {
		if id, ok := l.datagramRouter(buf); ok {
			if conn, ok := l.conns.Load(id); ok {
				return conn.(*PacketConn), true, nil //nolint:forcetypeassert
			}
		}
	}

	// If we don't have a custom resolver, or we were unable to find an
	// associated connection, fall back to remote address.
	conn, has := l.conns.Load(raddr.String())
	if !has { //nolint:nestif
		if isAccepting, ok := l.accepting.Load().(bool); !isAccepting || !ok {
			return nil, false, ErrClosedListener
		}
		if l.acceptFilter != nil {
			if !l.acceptFilter(buf) {
				return nil, false, nil
			}
		}
		conn, has = l.conns.LoadOrStore(raddr.String(), l.newPacketConn(raddr))
		if !has {
			select {
			case l.acceptCh <- conn.(*PacketConn): //nolint:forcetypeassert
				l.nConns.Add(1)
			default:
				l.conns.Delete(raddr.String())

				return nil, false, ErrListenQueueExceeded
			}
		}
	}

	return conn.(*PacketConn), true, nil //nolint:forcetypeassert
}

// PacketConn is a net.PacketConn implementation that is able to dictate its
// routing ID via an alternate identifier from its remote address. Internal
// buffering is performed for reads, and writes are passed through to the
// underlying net.PacketConn.
type PacketConn struct {
	listener *listener

	closeAccess sync.RWMutex
	closing     atomic.Bool
	raddr       atomic.Value // net.Addr
	id          atomic.Value // string

	buffer *idtlsnet.PacketBuffer

	doneCh chan struct{}

	writeDeadline *deadline.Deadline
}

// newPacketConn constructs a new PacketConn.
func (l *listener) newPacketConn(raddr net.Addr) *PacketConn {
	res := &PacketConn{
		listener:      l,
		buffer:        idtlsnet.NewPacketBuffer(),
		doneCh:        make(chan struct{}),
		writeDeadline: deadline.New(),
	}
	res.raddr.Store(raddr)

	return res
}

// ReadFrom reads a single packet payload and its associated remote address from
// the underlying buffer.
func (c *PacketConn) ReadFrom(buff []byte) (int, net.Addr, error) {
	return c.buffer.ReadFrom(buff)
}

// WriteTo writes len(payload) bytes from payload to the specified address.
func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (n int, err error) {
	c.closeAccess.RLock()
	defer c.closeAccess.RUnlock()
	if c.closing.Load() {
		return 0, io.EOF
	}

	// If we have a connection identifier, check to see if the outgoing packet
	// sets it.
	if c.listener.connIdentifier != nil {
		id := c.id.Load()
		// Only update establish identifier if we haven't already done so.
		if id == nil {
			candidate, ok := c.listener.connIdentifier(payload)
			// If we have an identifier, add entry to connection map.
			if ok {
				c.listener.conns.Store(candidate, c)
				c.id.Store(candidate)
			}
		}
		// If we are writing to a remote address that differs from the initial,
		// we have an alternate identifier established, and we haven't already
		// freed the remote address, free the remote address to be used by
		// another connection.
		// Note: this strategy results in holding onto a remote address after it
		// is potentially no longer in use by the client. However, releasing
		// earlier means that we could miss some packets that should have been
		// routed to this connection. Ideally, we would drop the connection
		// entry for the remote address as soon as the client starts sending
		// using an alternate identifier, but in practice this proves
		// challenging because any client could spoof a connection identifier,
		// resulting in the remote address entry being dropped prior to the
		// "real" client transitioning to sending using the alternate
		// identifier.
		old := c.raddr.Swap(addr)
		if old.(net.Addr).String() != addr.String() { //nolint:forcetypeassert
			c.listener.conns.Delete(old.(net.Addr).String()) //nolint:forcetypeassert
		}
	}

	select {
	case <-c.writeDeadline.Done():
		return 0, context.DeadlineExceeded
	default:
	}

	return c.listener.pConn.WriteTo(payload, addr)
}

// Close closes the conn and releases any Read calls.
func (c *PacketConn) Close() error {
	var err error
	if !c.closing.Swap(true) { //nolint:nestif
		c.listener.connWG.Done()
		close(c.doneCh)
		c.closeAccess.Lock()
		defer c.closeAccess.Unlock()

		// If we have an alternate identifier, remove it from the connection
		// map.
		id := c.id.Load()
		if id != nil {
			c.listener.conns.Delete(id.(string)) //nolint:forcetypeassert
		}
		c.listener.conns.Delete(c.raddr.Load().(net.Addr).String()) //nolint:forcetypeassert

		nConns := c.listener.nConns.Add(-1)

		if isAccepting, ok := c.listener.accepting.Load().(bool); nConns == 0 && !isAccepting && ok {
			// Wait if this is the final connection
			c.listener.readWG.Wait()
			if errClose, ok := c.listener.errClose.Load().(error); ok {
				err = errClose
			}
		} else {
			err = nil
		}

		if errBuf := c.buffer.Close(); errBuf != nil && err == nil {
			err = errBuf
		}
	}

	return err
}

// LocalAddr implements net.PacketConn.LocalAddr.
func (c *PacketConn) LocalAddr() net.Addr {
	return c.listener.pConn.LocalAddr()
}

// SetDeadline implements net.PacketConn.SetDeadline.
func (c *PacketConn) SetDeadline(t time.Time) error {
	c.writeDeadline.Set(t)

	return c.SetReadDeadline(t)
}

// SetReadDeadline implements net.PacketConn.SetReadDeadline.
func (c *PacketConn) SetReadDeadline(t time.Time) error {
	return c.buffer.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn.SetWriteDeadline.
func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	// Write deadline of underlying connection should not be changed
	// since the connection can be shared.
	return nil
}
