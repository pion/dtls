package dtls

import (
	"net"

	"github.com/pion/dtls/v2/internal/net/udp"
)

// Listen creates a DTLS listener
func Listen(network string, laddr *net.UDPAddr, config *Config) (net.Listener, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	parent, err := udp.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &listener{
		config: config,
		parent: parent,
	}, nil
}

// listener represents a DTLS listener
type listener struct {
	config *Config
	parent *udp.Listener
}

// Accept waits for and returns the next connection to the listener.
// You have to either close or read on all connection that are created.
// Connection handshake will timeout using ConnectContextMaker in the Config.
// If you want to specify the timeout duration, set ConnectContextMaker.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.parent.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.config)
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
// Already Accepted connections are not closed.
func (l *listener) Close() error {
	return l.parent.Close()
}

// Addr returns the listener's network address.
func (l *listener) Addr() net.Addr {
	return l.parent.Addr()
}
