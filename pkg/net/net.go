// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package net defines packet-oriented primitives that are compatible with net
// in the standard library.
package net

import "net"

// A PacketListener is the same as net.Listener but returns a net.PacketConn on
// Accept() rather than a net.Conn.
//
// Multiple goroutines may invoke methods on a PacketListener simultaneously.
type PacketListener interface {
	// Accept waits for and returns the next connection to the listener.
	Accept() (net.PacketConn, net.Addr, error)

	// Close closes the listener.
	// Any blocked Accept operations will be unblocked and return errors.
	Close() error

	// Addr returns the listener's network address.
	Addr() net.Addr
}

// PacketBufferRingbufferSize allows for setting the ring buffer size.
// A size of 0 (default), means the ring buffer will grow when full.
// If a size if provided, the packets will be dropped when the ring buffer is full.
var PacketBufferRingbufferSize = 0 //nolint:gochecknoglobals
