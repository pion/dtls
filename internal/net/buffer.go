// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package net implements DTLS specific networking primitives.
// NOTE: this package is an adaptation of pion/transport/packetio that allows for
// storing a remote address alongside each packet in the buffer and implements
// relevant methods of net.PacketConn. If possible, the updates made in this
// repository will be reflected back upstream. If not, it is likely that this
// will be moved to a public package in this repository.
//
// This package was migrated from pion/transport/packetio at
// https://github.com/pion/transport/commit/6890c795c807a617c054149eee40a69d7fdfbfdb
package net

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/transport/v4/deadline"
)

// ErrTimeout indicates that deadline was reached before operation could be
// completed.
var ErrTimeout = dtlserrors.ErrNetBufferTimeout

// AddrPacket is a packet payload and the associated remote address from which
// it was received.
type AddrPacket struct {
	addr net.Addr
	data *bytes.Buffer
}

// PacketBuffer is a circular buffer for network packets. Each slot in the
// buffer contains the remote address from which the packet was received, as
// well as the packet data.
type PacketBuffer struct {
	packets []AddrPacket

	write, read         atomic.Uint64
	readLock, writeLock sync.Mutex

	notify chan struct{}
	closed atomic.Bool

	readDeadline *deadline.Deadline
}

const defaultPacketSize = 128

// NewPacketBufferWithSize creates a new PacketBuffer with a given buffer size.
func NewPacketBufferWithSize(bufSize int) *PacketBuffer {
	if bufSize == 0 {
		bufSize = defaultPacketSize
	}

	return &PacketBuffer{
		readDeadline: deadline.New(),
		packets:      make([]AddrPacket, bufSize),
		notify:       make(chan struct{}, 1),
	}
}

// NewPacketBuffer creates a new PacketBuffer with default buffer size.
func NewPacketBuffer() *PacketBuffer {
	return NewPacketBufferWithSize(defaultPacketSize)
}

//nolint:gochecknoglobals
var bufferPool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

// WriteTo writes a single packet to the buffer. The supplied address will
// remain associated with the packet.
func (b *PacketBuffer) WriteTo(pkt []byte, addr net.Addr) (int, error) {
	b.writeLock.Lock()
	defer b.writeLock.Unlock()

	if b.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	write := b.write.Load()
	read := b.read.Load()

	if write-read >= uint64(len(b.packets)) {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	slot := &b.packets[write%uint64(len(b.packets))]

	buf := bufferPool.Get()
	slot.data, _ = buf.(*bytes.Buffer)
	slot.data.Reset()

	n, err := slot.data.Write(pkt)
	if err != nil {
		return n, err
	}

	slot.addr = addr

	b.write.Add(1)

	select {
	case b.notify <- struct{}{}:
	default:
	}

	return n, nil
}

// ReadFrom reads a single packet from the buffer, or blocks until one is
// available.
func (b *PacketBuffer) ReadFrom(packet []byte) (n int, addr net.Addr, err error) {
	b.readLock.Lock()

	select {
	case <-b.readDeadline.Done():
		b.readLock.Unlock()

		return 0, nil, ErrTimeout
	default:
	}

	for {
		read := b.read.Load()
		write := b.write.Load()

		if read < write {
			slot := &b.packets[read%uint64(len(b.packets))]

			if len(packet) < slot.data.Len() {
				b.readLock.Unlock()

				return 0, nil, io.ErrShortBuffer
			}

			n, err := slot.data.Read(packet)
			if err != nil {
				b.readLock.Unlock()

				return n, nil, err
			}

			addr = slot.addr

			bufferPool.Put(slot.data)
			slot.data = nil

			b.read.Add(1)
			b.readLock.Unlock()

			return n, addr, nil
		}

		if b.closed.Load() {
			b.readLock.Unlock()

			return 0, nil, io.EOF
		}

		b.readLock.Unlock()
		select {
		case <-b.readDeadline.Done():
			return 0, nil, ErrTimeout
		case <-b.notify:
			b.readLock.Lock()
		}
	}
}

// Close closes the buffer, allowing unread packets to be read, but erroring on
// any new writes.
func (b *PacketBuffer) Close() error {
	b.writeLock.Lock()
	defer b.writeLock.Unlock()

	b.readLock.Lock()
	defer b.readLock.Unlock()

	if !b.closed.CompareAndSwap(false, true) {
		return nil
	}

	select {
	case b.notify <- struct{}{}:
	default:
	}

	return nil
}

// SetReadDeadline sets the read deadline for the buffer.
func (b *PacketBuffer) SetReadDeadline(t time.Time) error {
	b.readLock.Lock()
	defer b.readLock.Unlock()
	b.readDeadline.Set(t)

	select {
	case b.notify <- struct{}{}:
	default:
	}

	return nil
}
