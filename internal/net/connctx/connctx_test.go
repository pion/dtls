package connctx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestRead(t *testing.T) {
	ca, cb := net.Pipe()
	defer func() {
		_ = ca.Close()
	}()

	data := []byte{0x01, 0x02, 0xFF}
	chErr := make(chan error)

	go func() {
		_, err := cb.Write(data)
		chErr <- err
	}()

	c := New(ca)
	b := make([]byte, 100)
	n, err := c.Read(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Errorf("Wrong data length, expected %d, got %d", len(data), n)
	}
	if !bytes.Equal(data, b[:n]) {
		t.Errorf("Wrong data, expected %v, got %v", data, b)
	}

	err = <-chErr
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadTImeout(t *testing.T) {
	ca, _ := net.Pipe()
	defer func() {
		_ = ca.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	c := New(ca)
	b := make([]byte, 100)
	n, err := c.Read(ctx, b)
	if err == nil {
		t.Error("Read unexpectedly successed")
	}
	if n != 0 {
		t.Errorf("Wrong data length, expected %d, got %d", 0, n)
	}
}

func TestReadCancel(t *testing.T) {
	ca, _ := net.Pipe()
	defer func() {
		_ = ca.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	c := New(ca)
	b := make([]byte, 100)
	n, err := c.Read(ctx, b)
	if err == nil {
		t.Error("Read unexpectedly successed")
	}
	if n != 0 {
		t.Errorf("Wrong data length, expected %d, got %d", 0, n)
	}
}

func TestReadClosed(t *testing.T) {
	ca, _ := net.Pipe()

	c := New(ca)
	_ = c.Close()

	b := make([]byte, 100)
	n, err := c.Read(context.Background(), b)
	if err != io.EOF {
		t.Errorf("Expected error '%v', got '%v'", io.EOF, err)
	}
	if n != 0 {
		t.Errorf("Wrong data length, expected %d, got %d", 0, n)
	}
}

func TestWrite(t *testing.T) {
	ca, cb := net.Pipe()
	defer func() {
		_ = ca.Close()
	}()

	chErr := make(chan error)
	chRead := make(chan []byte)

	go func() {
		b := make([]byte, 100)
		n, err := cb.Read(b)
		chErr <- err
		chRead <- b[:n]
	}()

	c := New(ca)
	data := []byte{0x01, 0x02, 0xFF}
	n, err := c.Write(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Errorf("Wrong data length, expected %d, got %d", len(data), n)
	}

	err = <-chErr
	b := <-chRead
	if !bytes.Equal(data, b) {
		t.Errorf("Wrong data, expected %v, got %v", data, b)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteTimeout(t *testing.T) {
	ca, _ := net.Pipe()
	defer func() {
		_ = ca.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	c := New(ca)
	b := make([]byte, 100)
	n, err := c.Write(ctx, b)
	if err == nil {
		t.Error("Write unexpectedly successed")
	}
	if n != 0 {
		t.Errorf("Wrong data length, expected %d, got %d", 0, n)
	}
}

func TestWriteCancel(t *testing.T) {
	ca, _ := net.Pipe()
	defer func() {
		_ = ca.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	c := New(ca)
	b := make([]byte, 100)
	n, err := c.Write(ctx, b)
	if err == nil {
		t.Error("Write unexpectedly successed")
	}
	if n != 0 {
		t.Errorf("Wrong data length, expected %d, got %d", 0, n)
	}
}

func TestWriteClosed(t *testing.T) {
	ca, _ := net.Pipe()

	c := New(ca)
	_ = c.Close()

	b := make([]byte, 100)
	n, err := c.Write(context.Background(), b)
	if !errors.Is(err, ErrClosing) {
		t.Errorf("Expected error '%v', got '%v'", ErrClosing, err)
	}
	if n != 0 {
		t.Errorf("Wrong data length, expected %d, got %d", 0, n)
	}
}

// Test for TestLocalAddrAndRemoteAddr
type stringAddr struct {
	network string
	addr    string
}

func (a stringAddr) Network() string { return a.network }
func (a stringAddr) String() string  { return a.addr }

type connAddrMock struct{}

func (*connAddrMock) RemoteAddr() net.Addr               { return stringAddr{"remote_net", "remote_addr"} }
func (*connAddrMock) LocalAddr() net.Addr                { return stringAddr{"local_net", "local_addr"} }
func (*connAddrMock) Read(b []byte) (n int, err error)   { panic("unimplemented") }
func (*connAddrMock) Write(b []byte) (n int, err error)  { panic("unimplemented") }
func (*connAddrMock) Close() error                       { panic("unimplemented") }
func (*connAddrMock) SetDeadline(t time.Time) error      { panic("unimplemented") }
func (*connAddrMock) SetReadDeadline(t time.Time) error  { panic("unimplemented") }
func (*connAddrMock) SetWriteDeadline(t time.Time) error { panic("unimplemented") }

func TestLocalAddrAndRemoteAddr(t *testing.T) {
	c := New(&connAddrMock{})
	al := c.LocalAddr()
	ar := c.RemoteAddr()

	if al.String() != "local_addr" {
		t.Error("Wrong LocalAddr implementation")
	}
	if ar.String() != "remote_addr" {
		t.Error("Wrong RemoteAddr implementation")
	}
}
