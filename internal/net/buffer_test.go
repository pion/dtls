// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package net implements DTLS specific networking primitives.
package net

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func equalInt(t *testing.T, expected, actual int) {
	t.Helper()

	assert.Equal(t, expected, actual)
}

func equalUDPAddr(t *testing.T, expected, actual net.Addr) {
	t.Helper()

	if expected == nil && actual == nil {
		return
	}
	assert.Equal(t, expected.String(), actual.String())
}

func equalBytes(t *testing.T, expected, actual []byte) {
	t.Helper()

	assert.Equal(t, expected, actual)
}

func TestBuffer(t *testing.T) {
	buffer := NewPacketBuffer()
	packet := make([]byte, 4)
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	assert.NoError(t, err)

	// Write once.
	n, err := buffer.WriteTo([]byte{0, 1}, addr)
	assert.NoError(t, err)
	equalInt(t, 2, n)

	// Read once.
	var raddr net.Addr
	n, raddr, err = buffer.ReadFrom(packet)
	assert.NoError(t, err)
	equalInt(t, 2, n)
	equalBytes(t, []byte{0, 1}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	// Read deadline.
	assert.NoError(t, buffer.SetReadDeadline(time.Unix(0, 1)))

	n, raddr, err = buffer.ReadFrom(packet)
	assert.ErrorIs(t, err, ErrTimeout)
	equalInt(t, 0, n)
	equalUDPAddr(t, nil, raddr)

	// Reset deadline.
	assert.NoError(t, buffer.SetReadDeadline(time.Time{}))

	// Write twice.
	n, err = buffer.WriteTo([]byte{2, 3, 4}, addr)
	assert.NoError(t, err)
	equalInt(t, 3, n)

	n, err = buffer.WriteTo([]byte{5, 6, 7}, addr)
	assert.NoError(t, err)
	equalInt(t, 3, n)

	// Read twice.
	n, raddr, err = buffer.ReadFrom(packet)
	assert.NoError(t, err)
	equalInt(t, 3, n)
	equalBytes(t, []byte{2, 3, 4}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	n, raddr, err = buffer.ReadFrom(packet)
	assert.NoError(t, err)
	equalInt(t, 3, n)
	equalBytes(t, []byte{5, 6, 7}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	// Write once prior to close.
	_, err = buffer.WriteTo([]byte{3}, addr)
	assert.NoError(t, err)

	// Close.
	assert.NoError(t, buffer.Close())

	// Future writes will error.
	_, err = buffer.WriteTo([]byte{4}, addr)
	assert.Error(t, err)

	// But we can read the remaining data.
	n, raddr, err = buffer.ReadFrom(packet)
	assert.NoError(t, err)
	equalInt(t, 1, n)
	equalBytes(t, []byte{3}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	// Until EOF.
	_, _, err = buffer.ReadFrom(packet)
	assert.ErrorIs(t, err, io.EOF)
}

func TestShortBuffer(t *testing.T) {
	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	assert.NoError(t, err)

	// Write once.
	n, err := buffer.WriteTo([]byte{0, 1, 2, 3}, addr)
	assert.NoError(t, err)
	equalInt(t, 4, n)

	// Try to read with a short buffer.
	packet := make([]byte, 3)
	var raddr net.Addr
	n, raddr, err = buffer.ReadFrom(packet)
	assert.ErrorIs(t, err, io.ErrShortBuffer)
	equalUDPAddr(t, nil, raddr)
	equalInt(t, 0, n)

	// Close.
	assert.NoError(t, buffer.Close())

	// Make sure you can Close twice.
	assert.NoError(t, buffer.Close())
}

func TestWraparound(t *testing.T) {
	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	assert.NoError(t, err)

	// Write multiple.
	n, err := buffer.WriteTo([]byte{0, 1, 2, 3}, addr)
	assert.NoError(t, err)
	equalInt(t, 4, n)

	n, err = buffer.WriteTo([]byte{4, 5}, addr)
	assert.NoError(t, err)
	equalInt(t, 2, n)

	n, err = buffer.WriteTo([]byte{6, 7, 8}, addr)
	assert.NoError(t, err)
	equalInt(t, 3, n)

	// Verify underlying buffer length.
	// Packet 1: buffer does not grow.
	// Packet 2: buffer doubles from 1 to 2.
	// Packet 3: buffer doubles from 2 to 4.
	equalInt(t, 4, len(buffer.packets))

	// Read once.
	packet := make([]byte, 4)
	var raddr net.Addr
	n, raddr, err = buffer.ReadFrom(packet)
	assert.NoError(t, err)
	equalInt(t, 4, n)
	equalBytes(t, []byte{0, 1, 2, 3}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	// Write again.
	n, err = buffer.WriteTo([]byte{9, 10, 11}, addr)
	assert.NoError(t, err)
	equalInt(t, 3, n)

	// Verify underlying buffer length.
	// No change in buffer size.
	equalInt(t, 4, len(buffer.packets))

	// Write again and verify buffer grew.
	n, err = buffer.WriteTo([]byte{12, 13, 14, 15, 16, 17, 18, 19}, addr)
	assert.NoError(t, err)
	equalInt(t, 8, n)
	equalInt(t, 4, len(buffer.packets))

	// Close.
	assert.NoError(t, buffer.Close())
}

func TestBufferAsync(t *testing.T) {
	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	assert.NoError(t, err)

	// Start up a goroutine to start a blocking read.
	done := make(chan string)
	go func() {
		packet := make([]byte, 4)

		n, raddr, rErr := buffer.ReadFrom(packet)
		if rErr != nil {
			done <- rErr.Error()

			return
		}

		equalInt(t, 2, n)
		equalBytes(t, []byte{0, 1}, packet[:n])
		equalUDPAddr(t, addr, raddr)

		_, _, readErr := buffer.ReadFrom(packet)
		if !errors.Is(readErr, io.EOF) {
			done <- fmt.Sprintf("Unexpected err %v wanted io.EOF", readErr)
		} else {
			close(done)
		}
	}()

	// Wait for the reader to start reading.
	time.Sleep(time.Millisecond)

	// Write once
	n, err := buffer.WriteTo([]byte{0, 1}, addr)
	assert.NoError(t, err)
	equalInt(t, 2, n)

	// Wait for the reader to start reading again.
	time.Sleep(time.Millisecond)

	// Close will unblock the reader.
	assert.NoError(t, buffer.Close())

	routineFail, ok := <-done
	assert.False(t, ok, routineFail)
}

func benchmarkBufferWR(b *testing.B, size int64, write bool, grow int) { // nolint:unparam
	b.Helper()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		b.Fatalf("net.ResolveUDPAddr: %v", err)
	}
	buffer := NewPacketBuffer()
	packet := make([]byte, size)

	// Grow the buffer first
	pad := make([]byte, 1022)
	for len(buffer.packets) < grow {
		_, err := buffer.WriteTo(pad, addr)
		assert.NoError(b, err)
	}
	for buffer.read != buffer.write {
		_, _, err := buffer.ReadFrom(pad)
		assert.NoError(b, err)
	}

	if write {
		_, err := buffer.WriteTo(packet, addr)
		assert.NoError(b, err)
	}

	b.SetBytes(size)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := buffer.WriteTo(packet, addr)
		assert.NoError(b, err)

		_, _, err = buffer.ReadFrom(packet)
		assert.NoError(b, err)
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

// Here, the buffer never becomes empty, which forces wraparound.
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
	b.Helper()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	assert.NoError(b, err)

	buffer := NewPacketBuffer()
	b.SetBytes(size)

	done := make(chan struct{})
	go func() {
		packet := make([]byte, size)

		for {
			_, _, err := buffer.ReadFrom(packet)
			if errors.Is(err, io.EOF) {
				break
			}
			assert.NoError(b, err)
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
		assert.NoError(b, err)
	}

	assert.NoError(b, buffer.Close())

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
