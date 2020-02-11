package dtls

import (
	"context"
	"net"
)

// Export extracts dtls state and inner connection from an already handshaked dtls conn
func (c *Conn) Export() (*State, net.Conn, error) {
	state, err := c.state.clone()
	if err != nil {
		return nil, nil, err
	}
	return state, c.nextConn, nil
}

// Resume imports an already stablished dtls connection using a specific dtls state
func Resume(state *State, conn net.Conn, config *Config) (*Conn, error) {
	// Custom flight handler that sets imported data and signals as handshaked
	flightHandler := func(c *Conn) (bool, *alert, error) {
		c.state = *state
		c.handshakeDoneSignal.Close()
		return true, nil, nil
	}

	// Empty handshake handler, since handshake was already done
	handshakeHandler := func(c *Conn) (*alert, error) {
		return nil, nil
	}

	c, err := createConn(context.Background(), conn, flightHandler, handshakeHandler, config, state.isClient)
	if err != nil {
		return nil, err
	}

	return c, c.handshakeErr.load()
}
