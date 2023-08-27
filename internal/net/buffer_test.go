// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package net implements DTLS specific networking primitives.
package net

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuffer(t *testing.T) {
	assert := assert.New(t)

	buffer := NewPacketBuffer()
	packet := make([]byte, 4)
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	assert.NoError(err)

	// Write once.
	n, err := buffer.WriteTo([]byte{0, 1}, addr)
	assert.NoError(err)
	assert.Equal(2, n)

	// Read once.
	var raddr net.Addr
	n, raddr, err = buffer.ReadFrom(packet)
	assert.NoError(err)
	assert.Equal(2, n)
	assert.Equal([]byte{0, 1}, packet[:n])
	assert.Equal(addr, raddr)

	// Read deadline.
	err = buffer.SetReadDeadline(time.Unix(0, 1))
	assert.NoError(err)
	n, raddr, err = buffer.ReadFrom(packet)
	assert.EqualError(err, ErrTimeout.Error())
	assert.Equal(0, n)
	assert.Equal(nil, raddr)

	// Reset deadline.
	err = buffer.SetReadDeadline(time.Time{})
	assert.NoError(err)

	// Write twice.
	n, err = buffer.WriteTo([]byte{2, 3, 4}, addr)
	assert.NoError(err)
	assert.Equal(3, n)

	n, err = buffer.WriteTo([]byte{5, 6, 7}, addr)
	assert.NoError(err)
	assert.Equal(3, n)

	// Read twice.
	n, raddr, err = buffer.ReadFrom(packet)
	assert.NoError(err)
	assert.Equal(3, n)
	assert.Equal([]byte{2, 3, 4}, packet[:n])
	assert.Equal(addr, raddr)

	n, raddr, err = buffer.ReadFrom(packet)
	assert.NoError(err)
	assert.Equal(3, n)
	assert.Equal([]byte{5, 6, 7}, packet[:n])
	assert.Equal(addr, raddr)

	// Write once prior to close.
	_, err = buffer.WriteTo([]byte{3}, addr)
	assert.NoError(err)

	// Close.
	assert.NoError(buffer.Close())

	// Future writes will error.
	_, err = buffer.WriteTo([]byte{4}, addr)
	assert.Error(err)

	// But we can read the remaining data.
	n, raddr, err = buffer.ReadFrom(packet)
	assert.NoError(err)
	assert.Equal(1, n)
	assert.Equal([]byte{3}, packet[:n])
	assert.Equal(addr, raddr)

	// Until EOF.
	_, _, err = buffer.ReadFrom(packet)
	assert.Equal(io.EOF, err)
}

func TestShortBuffer(t *testing.T) {
	assert := assert.New(t)

	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	assert.NoError(err)

	// Write once.
	n, err := buffer.WriteTo([]byte{0, 1, 2, 3}, addr)
	assert.NoError(err)
	assert.Equal(4, n)

	// Try to read with a short buffer.
	packet := make([]byte, 3)
	var raddr net.Addr
	n, raddr, err = buffer.ReadFrom(packet)
	assert.Equal(io.ErrShortBuffer, err)
	assert.Equal(nil, raddr)
	assert.Equal(0, n)

	// Close.
	assert.NoError(buffer.Close())

	// Make sure you can Close twice.
	assert.NoError(buffer.Close())
}

func TestWraparound(t *testing.T) {
	assert := assert.New(t)

	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	assert.NoError(err)

	// Write multiple.
	n, err := buffer.WriteTo([]byte{0, 1, 2, 3}, addr)
	assert.NoError(err)
	assert.Equal(4, n)

	n, err = buffer.WriteTo([]byte{4, 5}, addr)
	assert.NoError(err)
	assert.Equal(2, n)

	n, err = buffer.WriteTo([]byte{6, 7, 8}, addr)
	assert.NoError(err)
	assert.Equal(3, n)

	// Verify underlying buffer length.
	// Packet 1: buffer does not grow.
	// Packet 2: buffer doubles from 1 to 2.
	// Packet 3: buffer doubles from 2 to 4.
	assert.Equal(4, len(buffer.packets))

	// Read once.
	packet := make([]byte, 4)
	var raddr net.Addr
	n, raddr, err = buffer.ReadFrom(packet)
	assert.NoError(err)
	assert.Equal(4, n)
	assert.Equal([]byte{0, 1, 2, 3}, packet[:n])
	assert.Equal(addr, raddr)

	// Write again.
	n, err = buffer.WriteTo([]byte{9, 10, 11}, addr)
	assert.NoError(err)
	assert.Equal(3, n)

	// Verify underlying buffer length.
	// No change in buffer size.
	assert.Equal(4, len(buffer.packets))

	// Write again and verify buffer grew.
	n, err = buffer.WriteTo([]byte{12, 13, 14, 15, 16, 17, 18, 19}, addr)
	assert.NoError(err)
	assert.Equal(8, n)
	assert.Equal(4, len(buffer.packets))

	// Close.
	assert.NoError(buffer.Close())
}

func TestBufferAsync(t *testing.T) {
	assert := assert.New(t)

	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	assert.NoError(err)

	// Start up a goroutine to start a blocking read.
	done := make(chan struct{})
	go func() {
		packet := make([]byte, 4)

		n, raddr, rErr := buffer.ReadFrom(packet)
		assert.NoError(rErr)
		assert.Equal(2, n)
		assert.Equal([]byte{0, 1}, packet[:n])
		assert.Equal(addr, raddr)

		_, _, err = buffer.ReadFrom(packet)
		assert.Equal(io.EOF, err)

		close(done)
	}()

	// Wait for the reader to start reading.
	time.Sleep(time.Millisecond)

	// Write once
	n, err := buffer.WriteTo([]byte{0, 1}, addr)
	assert.NoError(err)
	assert.Equal(2, n)

	// Wait for the reader to start reading again.
	time.Sleep(time.Millisecond)

	// Close will unblock the reader.
	assert.NoError(buffer.Close())

	<-done
}

func benchmarkBufferWR(b *testing.B, size int64, write bool, grow int) { // nolint:unparam
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		b.Fatalf("net.ResolveUDPAddr: %v", err)
	}
	buffer := NewPacketBuffer()
	packet := make([]byte, size)

	// Grow the buffer first
	pad := make([]byte, 1022)
	for len(buffer.packets) < grow {
		if _, err := buffer.WriteTo(pad, addr); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}
	for buffer.read != buffer.write {
		if _, _, err := buffer.ReadFrom(pad); err != nil {
			b.Fatalf("ReadFrom: %v", err)
		}
	}

	if write {
		if _, err := buffer.WriteTo(packet, addr); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}

	b.SetBytes(size)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := buffer.WriteTo(packet, addr); err != nil {
			b.Fatalf("Write: %v", err)
		}
		if _, _, err := buffer.ReadFrom(packet); err != nil {
			b.Fatalf("Write: %v", err)
		}
	}
}

// In this benchmark, the buffer is often empty, which is hopefully
// typical of real usage.
func BenchmarkBufferWR14(b *testing.B) {
	benchmarkBufferWR(b, 14, false, 128)
}

func BenchmarkBufferWR140(b *testing.B) {
	benchmarkBufferWR(b, 140, false, 128)
}

func BenchmarkBufferWR1400(b *testing.B) {
	benchmarkBufferWR(b, 1400, false, 128)
}

// Here, the buffer never becomes empty, which forces wraparound
func BenchmarkBufferWWR14(b *testing.B) {
	benchmarkBufferWR(b, 14, true, 128)
}

func BenchmarkBufferWWR140(b *testing.B) {
	benchmarkBufferWR(b, 140, true, 128)
}

func BenchmarkBufferWWR1400(b *testing.B) {
	benchmarkBufferWR(b, 1400, true, 128)
}

func benchmarkBuffer(b *testing.B, size int64) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		b.Fatalf("net.ResolveUDPAddr: %v", err)
	}
	buffer := NewPacketBuffer()
	b.SetBytes(size)

	done := make(chan struct{})
	go func() {
		packet := make([]byte, size)

		for {
			_, _, err := buffer.ReadFrom(packet)
			if errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				b.Error(err)
				break
			}
		}

		close(done)
	}()

	packet := make([]byte, size)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var err error
		for {
			_, err = buffer.WriteTo(packet, addr)
			if !errors.Is(err, bytes.ErrTooLarge) {
				break
			}
			time.Sleep(time.Microsecond)
		}
		if err != nil {
			b.Fatal(err)
		}
	}

	if err := buffer.Close(); err != nil {
		b.Fatal(err)
	}

	<-done
}

func BenchmarkBuffer14(b *testing.B) {
	benchmarkBuffer(b, 14)
}

func BenchmarkBuffer140(b *testing.B) {
	benchmarkBuffer(b, 140)
}

func BenchmarkBuffer1400(b *testing.B) {
	benchmarkBuffer(b, 1400)
}
