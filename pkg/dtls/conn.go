package dtls

import "net"

// Dial establishes a DTLS connection
// NOTE: we can remove this, just added it for research/planning ahead.
func Dial(network, address string) (*Conn, error) {
	return nil, errNotImplemented
}

// DialConn establishes a DTLS connection over an existing conn
func DialConn(conn net.Conn) (*Conn, error) {
	// TODO: Start a handshake on conn and complete it before
	// returning to ensure supplying an open Conn to avoid the need
	// for an 'OnOpen' callback.

	res := &Conn{
		conn: conn,
	}

	return res, nil
}

// Listen listens for incoming DTLS connections
// NOTE: we can remove this, just added it for research/planning ahead.
func Listen(network, address string) (*Listener, error) {
	// Probably easiest if it has it's own listener object.
	return nil, errNotImplemented
}

// Listener is the same as ConnListener but for directly listening on a socket.
// NOTE: we can remove this, just added it for research/planning ahead.
type Listener struct{}

// ListenConn listens for incoming DTLS connections over an existing conn
func ListenConn(conn net.Conn) (*ConnListener, error) {
	return &ConnListener{
		conn: conn,
	}, nil
}

// ConnListener listens for incoming DTLS connections over an existing connection
type ConnListener struct {
	conn net.Conn
}

// Accept waits for and returns the next DTLS connection.
func (l *ConnListener) Accept() (*Conn, error) {
	// TODO: Wait for a handshake on l.conn and complete it before
	// returning to ensure supplying an open Conn to avoid the need
	// for an 'OnOpen' callback.

	res := &Conn{
		conn: l.conn,
	}

	return res, nil
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *ConnListener) Close() error {
	// TODO: Kill the handshake if it is in progress
	// TODO: Unblock any calls to Accept
	return nil
}

// Addr returns the listener's network address.
// NOTE: we can remove this, just added it for research/planning ahead.
func (l *ConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// Conn represents a DTLS connection
type Conn struct {
	conn net.Conn
}

// Read reads data from the connection.
// NOTE: This can be more sophisticated to handle other DTLS protocol packets, etc.
func (c *Conn) Read(p []byte) (n int, err error) {
	n, err = c.conn.Read(p)
	if err != nil {
		return
	}

	// TODO: decrypt the bytes

	if len(p) < n {
		return 0, errBufferTooSmall // Note: Could return the result over multiple calls to Read.
	}

	return
}

// Write writes len(p) bytes from p to the DTLS connection
func (c *Conn) Write(p []byte) (n int, err error) {

	// TODO: encrypt the bytes

	n, err = c.conn.Write(p) // TODO: Write multiple times if n < len(p)
	if err != nil {
		return
	}

	return
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *Conn) Close() error {
	// TODO: Cleanup
	// TODO: Unblock any calls to Read or Write.
	return errNotImplemented
}
