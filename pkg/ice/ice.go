package ice

import (
	"net"
	"time"
)

// Agent is a faux ICE agent
type Agent struct {
	udpConn net.PacketConn
	cache   chan []byte

	dst *net.UDPAddr
}

// Listen creates a new listening Agent
func Listen(listenAddr string, dstAddr *net.UDPAddr) (*Agent, error) {
	pc, err := net.ListenPacket("udp4", listenAddr)
	if err != nil {
		panic(err)
	}

	a := &Agent{
		udpConn: pc,
		cache:   make(chan []byte, 100),
		dst:     dstAddr,
	}
	go func() {
		b := make([]byte, 8192)
		for {
			i, _, err := a.udpConn.ReadFrom(b)
			if err != nil {
				panic(err)
			}
			a.cache <- append([]byte{}, b[:i]...)
		}
	}()

	return a, nil
}

func (a *Agent) Read(p []byte) (int, error) {
	out := <-a.cache
	if len(p) < len(out) {
		panic("Buffer too small")
	}

	copy(p, out)
	return len(p), nil
}

// Write writes len(p) bytes from p to the DTLS connection
func (a *Agent) Write(p []byte) (n int, err error) {
	return a.udpConn.WriteTo(p, a.dst)
}

// Close is a stub
func (a *Agent) Close() error {
	return nil
}

// LocalAddr is a stub
func (a *Agent) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr is a stub
func (a *Agent) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline is a stub
func (a *Agent) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline is a stub
func (a *Agent) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline is a stub
func (a *Agent) SetWriteDeadline(t time.Time) error {
	return nil
}
