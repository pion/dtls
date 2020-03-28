package dtls

import (
	"context"
	"net"
)

// Export extracts dtls state and inner connection from an already handshaked dtls conn
func (c *Conn) Export() (*State, net.Conn, error) {
	state := c.state.clone()
	return state, c.nextConn.Conn(), nil
}

// Resume imports an already stablished dtls connection using a specific dtls state
func Resume(state *State, conn net.Conn, config *Config) (*Conn, error) {
	if err := state.initCipherSuite(); err != nil {
		return nil, err
	}
	c, err := createConn(context.Background(), conn, config, state.isClient, state)
	if err != nil {
		return nil, err
	}

	return c, nil
}
