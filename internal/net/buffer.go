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
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v4/deadline"
)

// ErrTimeout indicates that deadline was reached before operation could be
// completed.
var ErrTimeout = dtlserrors.ErrNetBufferTimeout

// AddrPacket is a packet payload and the associated remote address from which
// it was received.
type AddrPacket struct {
	addr net.Addr
	data bytes.Buffer
}

type readNotification struct {
	ch      chan struct{}
	waiters atomic.Int64
}

func newReadNotification() *readNotification {
	return &readNotification{ch: make(chan struct{})}
}

// PacketBuffer is a circular buffer for network packets. Each slot in the
// buffer contains the remote address from which the packet was received, as
// well as the packet data.
type PacketBuffer struct {
	packets  []AddrPacket
	growable bool

	write, read         atomic.Uint64
	readLock, writeLock sync.Mutex

	notify   atomic.Pointer[readNotification]
	closedCh chan struct{}
	closed   atomic.Bool

	readDeadline *deadline.Deadline
}

// NewPacketBufferWithSize creates a new PacketBuffer with a given buffer size.
// If the size is 0 (default), the ring buffer is unbounded and will grow indefinitely.
func NewPacketBufferWithSize(bufSize int) *PacketBuffer {
	growable := bufSize == 0
	if growable {
		bufSize = 1
	}

	buffer := &PacketBuffer{
		readDeadline: deadline.New(),
		packets:      make([]AddrPacket, bufSize),
		closedCh:     make(chan struct{}),
		growable:     growable,
	}
	buffer.notify.Store(newReadNotification())

	return buffer
}

// NewPacketBuffer creates a new PacketBuffer with default buffer size.
func NewPacketBuffer() *PacketBuffer {
	return NewPacketBufferWithSize(dtlsnet.PacketBufferRingbufferSize)
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
		if !b.growable {
			return 0, dtlserrors.ErrBufferTooSmall
		}
		b.readLock.Lock()
		read = b.read.Load()

		if write-read >= uint64(len(b.packets)) {
			oldLen := len(b.packets)
			newLen := oldLen * 2

			packets := make([]AddrPacket, newLen)
			for i := read; i < write; i++ {
				packets[i%uint64(newLen)] = b.packets[i%uint64(oldLen)]
			}

			b.packets = packets
		}
		b.readLock.Unlock()
	}

	slot := &b.packets[write%uint64(len(b.packets))]

	slot.data.Reset()

	n, err := slot.data.Write(pkt)
	if err != nil {
		return n, err
	}

	slot.addr = addr

	b.write.Add(1)

	b.notifyReaders()

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

			n, err = slot.data.Read(packet)
			if err != nil {
				b.readLock.Unlock()

				return n, nil, err
			}

			addr = slot.addr

			b.read.Add(1)
			b.readLock.Unlock()

			return n, addr, nil
		}

		if b.closed.Load() {
			b.readLock.Unlock()

			return 0, nil, io.EOF
		}

		b.readLock.Unlock()
		if err = b.waitForRead(); err != nil {
			return 0, nil, ErrTimeout
		}
		b.readLock.Lock()
	}
}

func (b *PacketBuffer) waitForRead() error {
	notify := b.notify.Load()
	notify.waiters.Add(1)

	if b.notify.Load() != notify || b.read.Load() < b.write.Load() || b.closed.Load() {
		notify.waiters.Add(-1)

		return nil
	}

	var err error
	select {
	case <-b.readDeadline.Done():
		err = ErrTimeout
	case <-notify.ch:
	case <-b.closedCh:
	}

	notify.waiters.Add(-1)

	return err
}

func (b *PacketBuffer) notifyReaders() {
	notify := b.notify.Load()
	if notify.waiters.Load() == 0 {
		return
	}

	if b.notify.CompareAndSwap(notify, newReadNotification()) {
		close(notify.ch)
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

	close(b.closedCh)

	return nil
}

// SetReadDeadline sets the read deadline for the buffer.
func (b *PacketBuffer) SetReadDeadline(t time.Time) error {
	b.readLock.Lock()
	defer b.readLock.Unlock()
	b.readDeadline.Set(t)

	b.notifyReaders()

	return nil
}
