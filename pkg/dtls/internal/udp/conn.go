package udp

import (
	"fmt"
	"net"
	"sync"
	"time"
)

const receiveMTU = 8192

// Listener augments a connection-oriented Listener over a UDP PacketConn
type Listener struct {
	pConn *net.UDPConn

	lock     sync.RWMutex
	acceptCh chan *Conn
	conns    map[string]*Conn
}

// Accept waits for and returns the next connection to the listener.
// You have to either close or read on all connection that are created.
func (l *Listener) Accept() (*Conn, error) {
	c := <-l.acceptCh
	return c, nil
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *Listener) Close() error {

	if len(l.conns) == 0 {
		return l.pConn.Close()
	}
	return nil
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.pConn.LocalAddr()
}

// Listen creates a new listener
func Listen(network string, laddr *net.UDPAddr) (*Listener, error) {
	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		pConn:    conn,
		acceptCh: make(chan *Conn),
		conns:    make(map[string]*Conn),
	}

	go l.readLoop()

	return l, nil
}

func (l *Listener) readLoop() {
	buf := make([]byte, receiveMTU)
	for {
		n, raddr, err := l.pConn.ReadFrom(buf)
		if err != nil {
			fmt.Println("Reading err", err)
			// TODO: close
		}
		conn, ok := l.conns[raddr.String()]
		if !ok {
			conn = newConn(l.pConn, raddr)
			l.conns[raddr.String()] = conn
			l.acceptCh <- conn
		}
		cBuf := <-conn.readCh
		n = copy(cBuf, buf[:n])
		conn.sizeCh <- n
	}
}

// Conn augments a connection-oriented connection over a UDP PacketConn
type Conn struct {
	pConn *net.UDPConn
	rAddr net.Addr

	readCh chan []byte
	sizeCh chan int
}

func newConn(pConn *net.UDPConn, rAddr net.Addr) *Conn {
	return &Conn{
		pConn:  pConn,
		rAddr:  rAddr,
		readCh: make(chan []byte),
		sizeCh: make(chan int),
	}
}

// Read
func (c *Conn) Read(p []byte) (int, error) {
	c.readCh <- p
	n := <-c.sizeCh

	return n, nil
}

// Write writes len(p) bytes from p to the DTLS connection
func (c *Conn) Write(p []byte) (n int, err error) {
	return c.pConn.WriteTo(p, c.rAddr)
}

// Close is a stub
func (c *Conn) Close() error {
	return c.pConn.Close()
}

// LocalAddr is a stub
func (c *Conn) LocalAddr() net.Addr {
	return c.pConn.LocalAddr()
}

// RemoteAddr is a stub
func (c *Conn) RemoteAddr() net.Addr {
	return c.rAddr
}

// SetDeadline is a stub
func (c *Conn) SetDeadline(t time.Time) error {
	return c.pConn.SetDeadline(t)
}

// SetReadDeadline is a stub
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.pConn.SetReadDeadline(t)
}

// SetWriteDeadline is a stub
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.pConn.SetWriteDeadline(t)
}
