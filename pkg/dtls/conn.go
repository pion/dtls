package dtls

// Conn represents a DTLS connection
type Conn struct {
	isClient bool

	outbound chan []byte // make(chan int)
}

// Start begins the DTLS connection
func Start(isClient bool) (*Conn, error) {
	return &Conn{
		isClient: isClient,
	}, nil
}

// Read reads up to len(p) bytes into p
func (c *Conn) Read(p []byte) (n int, err error) {
	out := <-c.outbound
	if len(p) < len(out) {
		return 0, errBufferTooSmall
	}

	copy(p, out)
	return len(p), nil
}

// Write writes len(p) bytes from p to the DTLS connection
func (c *Conn) Write(p []byte) (n int, err error) {
	return 0, errNotImplemented
}

// Close closes the DTLS connection
func (c *Conn) Close() error {
	return errNotImplemented
}
