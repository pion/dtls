// Package dpipe provides the pipe works like datagram protocol on memory.
package dpipe

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var errNotImplemented = errors.New("not implemented yet")

// Pipe creates pair of non-stream conn on memory.
// Close of the one end doesn't make effect to the other end.
func Pipe() (net.Conn, net.Conn) {
	ch0 := make(chan []byte, 1000)
	ch1 := make(chan []byte, 1000)
	return &conn{
			rCh:    ch0,
			wCh:    ch1,
			closed: make(chan struct{}),
		}, &conn{
			rCh:    ch1,
			wCh:    ch0,
			closed: make(chan struct{}),
		}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

type conn struct {
	rCh       chan []byte
	wCh       chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func (*conn) LocalAddr() net.Addr  { return pipeAddr{} }
func (*conn) RemoteAddr() net.Addr { return pipeAddr{} }

func (*conn) SetDeadline(t time.Time) error {
	return errNotImplemented
}
func (*conn) SetReadDeadline(t time.Time) error {
	return errNotImplemented
}
func (*conn) SetWriteDeadline(t time.Time) error {
	return errNotImplemented
}

func (c *conn) Read(data []byte) (n int, err error) {
	select {
	case <-c.closed:
		return 0, io.EOF
	default:
	}
	select {
	case d := <-c.rCh:
		if len(d) <= len(data) {
			copy(data, d)
			return len(d), nil
		}
		copy(data, d[:len(data)])
		return len(data), nil
	case <-c.closed:
		return 0, io.EOF
	}
}

func (c *conn) Write(data []byte) (n int, err error) {
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	case c.wCh <- data:
	}
	return len(data), nil
}

func (c *conn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
