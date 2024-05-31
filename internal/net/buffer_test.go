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
)

func equalInt(t *testing.T, expected, actual int) {
	if expected != actual {
		t.Errorf("Expected %d got %d", expected, actual)
	}
}

func equalUDPAddr(t *testing.T, expected, actual net.Addr) {
	if expected == nil && actual == nil {
		return
	}
	if expected.String() != actual.String() {
		t.Errorf("Expected %v got %v", expected, actual)
	}
}

func equalBytes(t *testing.T, expected, actual []byte) {
	if !bytes.Equal(expected, actual) {
		t.Errorf("Expected %v got %v", expected, actual)
	}
}

func TestBuffer(t *testing.T) {
	buffer := NewPacketBuffer()
	packet := make([]byte, 4)
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		t.Fatal(err)
	}

	// Write once.
	n, err := buffer.WriteTo([]byte{0, 1}, addr)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 2, n)

	// Read once.
	var raddr net.Addr
	if n, raddr, err = buffer.ReadFrom(packet); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 2, n)
	equalBytes(t, []byte{0, 1}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	// Read deadline.
	if err = buffer.SetReadDeadline(time.Unix(0, 1)); err != nil {
		t.Fatal(err)
	}
	n, raddr, err = buffer.ReadFrom(packet)
	if !errors.Is(ErrTimeout, err) {
		t.Fatalf("Unexpected err %v wanted ErrTimeout", err)
	}
	equalInt(t, 0, n)
	equalUDPAddr(t, nil, raddr)

	// Reset deadline.
	if err = buffer.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	// Write twice.
	if n, err = buffer.WriteTo([]byte{2, 3, 4}, addr); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 3, n)

	if n, err = buffer.WriteTo([]byte{5, 6, 7}, addr); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 3, n)

	// Read twice.
	if n, raddr, err = buffer.ReadFrom(packet); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 3, n)
	equalBytes(t, []byte{2, 3, 4}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	if n, raddr, err = buffer.ReadFrom(packet); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 3, n)
	equalBytes(t, []byte{5, 6, 7}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	// Write once prior to close.
	if _, err = buffer.WriteTo([]byte{3}, addr); err != nil {
		t.Fatal(err)
	}

	// Close.
	if err = buffer.Close(); err != nil {
		t.Fatal(err)
	}

	// Future writes will error.
	if _, err = buffer.WriteTo([]byte{4}, addr); err == nil {
		t.Fatal("Expected error")
	}

	// But we can read the remaining data.
	if n, raddr, err = buffer.ReadFrom(packet); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 1, n)
	equalBytes(t, []byte{3}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	// Until EOF.
	if _, _, err = buffer.ReadFrom(packet); !errors.Is(io.EOF, err) {
		t.Fatalf("Unexpected err %v wanted io.EOF", err)
	}
}

func TestShortBuffer(t *testing.T) {
	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		t.Fatal(err)
	}

	// Write once.
	n, err := buffer.WriteTo([]byte{0, 1, 2, 3}, addr)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 4, n)

	// Try to read with a short buffer.
	packet := make([]byte, 3)
	var raddr net.Addr
	n, raddr, err = buffer.ReadFrom(packet)
	if !errors.Is(io.ErrShortBuffer, err) {
		t.Fatalf("Unexpected err %v wanted io.ErrShortBuffer", err)
	}
	equalUDPAddr(t, nil, raddr)
	equalInt(t, 0, n)

	// Close.
	if err = buffer.Close(); err != nil {
		t.Fatal(err)
	}

	// Make sure you can Close twice.
	if err = buffer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWraparound(t *testing.T) {
	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		t.Fatal(err)
	}

	// Write multiple.
	n, err := buffer.WriteTo([]byte{0, 1, 2, 3}, addr)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 4, n)

	if n, err = buffer.WriteTo([]byte{4, 5}, addr); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 2, n)

	if n, err = buffer.WriteTo([]byte{6, 7, 8}, addr); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 3, n)

	// Verify underlying buffer length.
	// Packet 1: buffer does not grow.
	// Packet 2: buffer doubles from 1 to 2.
	// Packet 3: buffer doubles from 2 to 4.
	equalInt(t, 4, len(buffer.packets))

	// Read once.
	packet := make([]byte, 4)
	var raddr net.Addr
	if n, raddr, err = buffer.ReadFrom(packet); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 4, n)
	equalBytes(t, []byte{0, 1, 2, 3}, packet[:n])
	equalUDPAddr(t, addr, raddr)

	// Write again.
	if n, err = buffer.WriteTo([]byte{9, 10, 11}, addr); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 3, n)

	// Verify underlying buffer length.
	// No change in buffer size.
	equalInt(t, 4, len(buffer.packets))

	// Write again and verify buffer grew.
	if n, err = buffer.WriteTo([]byte{12, 13, 14, 15, 16, 17, 18, 19}, addr); err != nil {
		t.Fatal(err)
	}
	equalInt(t, 8, n)
	equalInt(t, 4, len(buffer.packets))

	// Close.
	if err = buffer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBufferAsync(t *testing.T) {
	buffer := NewPacketBuffer()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5684")
	if err != nil {
		t.Fatal(err)
	}

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
		if !errors.Is(io.EOF, readErr) {
			done <- fmt.Sprintf("Unexpected err %v wanted io.EOF", readErr)
		} else {
			close(done)
		}
	}()

	// Wait for the reader to start reading.
	time.Sleep(time.Millisecond)

	// Write once
	n, err := buffer.WriteTo([]byte{0, 1}, addr)
	if err != nil {
		t.Fatal(err)
	}
	equalInt(t, 2, n)

	// Wait for the reader to start reading again.
	time.Sleep(time.Millisecond)

	// Close will unblock the reader.
	if err = buffer.Close(); err != nil {
		t.Fatal(err)
	}

	if routineFail, ok := <-done; ok {
		t.Fatal(routineFail)
	}
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
