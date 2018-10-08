package dtls

import (
	"fmt"
	"net"
	"time"
)

// Conn represents a DTLS connection
type Conn struct {
	nextConn net.Conn

	isClient   bool // Should we start the handshake
	currFlight flight

	// Decrypted Application Data, Accessed by calling `Read`
	decrypted chan []byte

	workerTicker *time.Ticker
}

func createConn(isClient bool, nextConn net.Conn) *Conn {

	c := &Conn{
		nextConn:   nextConn,
		isClient:   isClient,
		currFlight: newFlight(isClient),

		decrypted:    make(chan []byte),
		workerTicker: time.NewTicker(1 * time.Second),
	}

	go c.readThread()
	go c.timerThread()
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
func (c *Conn) Close() error {
	c.nextConn.Close() // TODO Is there a better way to stop read in readThread?
	return nil
}

// Pulls from nextConn
func (c *Conn) readThread() {
	b := make([]byte, 8192)
	for {
		i, err := c.nextConn.Read(b)
		if err != nil {
			panic(err)
		}
		c.handleIncoming(b[:i])
	}
}

// Handles scheduled tasks like sending ClientHello
func (c *Conn) timerThread() {
	for range c.workerTicker.C {
		fmt.Println("tick")
	}
}

func (c *Conn) handleIncoming(buf []byte) {
	pkts, err := decodeUDPPacket(buf)
	if err != nil {
		panic(err)
	}

	// TODO handle+process
	fmt.Println(pkts)
}
