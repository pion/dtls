// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"net"

	"github.com/pion/dtls/v2/internal/net/udp"
	dtlsnet "github.com/pion/dtls/v2/pkg/net"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
)

// Listen creates a DTLS listener
func Listen(network string, laddr *net.UDPAddr, config *Config) (net.Listener, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	lc := udp.ListenConfig{
		AcceptFilter: func(packet []byte) bool {
			pkts, err := recordlayer.UnpackDatagram(packet)
			if err != nil || len(pkts) < 1 {
				return false
			}
			h := &recordlayer.Header{}
			if err := h.Unmarshal(pkts[0]); err != nil {
				return false
			}
			return h.ContentType == protocol.ContentTypeHandshake
		},
	}
	// If connection ID support is enabled, then they must be supported in
	// routing.
	if config.ConnectionIDGenerator != nil {
		lc.DatagramRouter = cidDatagramRouter(len(config.ConnectionIDGenerator()))
		lc.ConnectionIdentifier = cidConnIdentifier()
	}
	parent, err := lc.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &listener{
		config: config,
		parent: parent,
	}, nil
}

// NewListener creates a DTLS listener which accepts connections from an inner Listener.
func NewListener(inner dtlsnet.PacketListener, config *Config) (net.Listener, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return &listener{
		config: config,
		parent: inner,
	}, nil
}

// listener represents a DTLS listener
type listener struct {
	config *Config
	parent dtlsnet.PacketListener
}

// Handshaker performs handshakes and returns a connection, on success.
// It is only valid for 1 connection.
type Handshaker interface {
	Handshake() (net.Conn, error)
}

// handshaker implements Handshaker for a dtls connection.
type handshaker struct {
	parent net.PacketConn
	addr net.Addr
	config *Config
}

// Handshake performs a dtls handshake according to the bound config.
func (h handshaker) Handshake() (net.Conn, error) {
	return Server(h.parent, h.addr, h.config)
}

// AcceptHandshake accepts a connection and returns a Handshaker.
// This allows multiple handshakes to be performed in parallel.
func (l *listener) AcceptHandshake() (Handshaker, error) {
	c, raddr, err := l.parent.Accept()
	if err != nil {
		return nil, err
	}
	return handshaker{c, raddr, l.config}, err
}

// Accept waits for and returns the next connection to the listener.
// You have to either close or read on all connection that are created.
// Connection handshake will timeout using ConnectContextMaker in the Config.
// If you want to specify the timeout duration, set ConnectContextMaker.
func (l *listener) Accept() (net.Conn, error) {
	c, raddr, err := l.parent.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, raddr, l.config)
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
