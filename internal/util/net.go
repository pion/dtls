// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package util contains small helpers used across the repo
package util

import (
	"net"
	"time"
)

// packetConn wraps a net.Conn with methods that satisfy net.PacketConn.
type packetConn struct {
	conn net.Conn
}

// FromConn converts a net.Conn into a net.PacketConn.
func FromConn(conn net.Conn) net.PacketConn {
	return &packetConn{conn}
}

// ReadFrom reads from the underlying net.Conn and returns its remote address.
func (cp *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := cp.conn.Read(b)
	return n, cp.conn.RemoteAddr(), err
}

// WriteTo writes to the underlying net.Conn.
func (cp *packetConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	n, err := cp.conn.Write(b)
	return n, err
}

// Close closes the underlying net.Conn.
func (cp *packetConn) Close() error {
	return cp.conn.Close()
}

// LocalAddr returns the local address of the underlying net.Conn.
func (cp *packetConn) LocalAddr() net.Addr {
	return cp.conn.LocalAddr()
}

// SetDeadline sets the deadline on the underlying net.Conn.
func (cp *packetConn) SetDeadline(t time.Time) error {
	return cp.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying net.Conn.
func (cp *packetConn) SetReadDeadline(t time.Time) error {
	return cp.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying net.Conn.
func (cp *packetConn) SetWriteDeadline(t time.Time) error {
	return cp.conn.SetWriteDeadline(t)
}
