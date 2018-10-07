package dtls

import (
	"fmt"
	"net"
)

// Conn represents a DTLS connection
type Conn struct {
	nextConn net.Conn
	isClient bool

	// Decrypted Application Data, Accessed by calling `Read`
	decrypted chan []byte

	// closeNotify is used to close goroutine reading from nextConn
	closeNotify chan bool
}

func createConn(isClient bool, nextConn net.Conn) *Conn {
	c := &Conn{
		nextConn:    nextConn,
		isClient:    isClient,
		decrypted:   make(chan []byte),
		closeNotify: make(chan bool),
	}

	go func() {
		b := make([]byte, 8192)
		for {
			i, err := nextConn.Read(b)
			if err != nil {
				panic(err)
			}
			c.handleIncoming(b[:i])
		}
	}()

	return c
}

// Dial establishes a DTLS connection over an existing conn
func Dial(conn net.Conn) (*Conn, error) {
	return createConn( /*isClient*/ true, conn), nil
}

// Server listens for incoming DTLS connections
func Server(conn net.Conn) (*Conn, error) {
	return createConn( /*isClient*/ false, conn), nil
}

// Read reads data from the connection.
func (c *Conn) Read(p []byte) (n int, err error) {
	out := <-c.decrypted
	if len(p) < len(out) {
		return 0, errBufferTooSmall
	}

	copy(p, out)
	return len(p), nil
}

// Write writes len(p) bytes from p to the DTLS connection
func (c *Conn) Write(p []byte) (n int, err error) {
	return // TODO encrypt + send ApplicationData
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *Conn) Close() error {
	return errNotImplemented
}

func (c *Conn) handleIncoming(buf []byte) {
	pkts, err := decodeUDPPacket(buf)
	if err != nil {
		panic(err)
	}

	// TODO handle+process
	fmt.Println(pkts)
}
