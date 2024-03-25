// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build aix || darwin || dragonfly || freebsd || linux || nacl || nacljs || netbsd || openbsd || solaris || windows
// +build aix darwin dragonfly freebsd linux nacl nacljs netbsd openbsd solaris windows

// For systems having syscall.Errno.
// The build target must be same as errors_errno.go.

package dtls

import (
	"errors"
	"net"
	"testing"
)

func TestErrorsTemporary(t *testing.T) {
	// Allocate a UDP port no one is listening on.
	addrListen, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		t.Fatalf("Unexpected failure to resolve: %v", err)
	}
	listener, err := net.ListenUDP("udp", addrListen)
	if err != nil {
		t.Fatalf("Unexpected failure to listen: %v", err)
	}
	raddr, ok := listener.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("Unexpedted type assertion error")
	}
	err = listener.Close()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Server is not listening.
	conn, errDial := net.DialUDP("udp", nil, raddr)
	if errDial != nil {
		t.Fatalf("Unexpected error: %v", errDial)
	}

	_, _ = conn.Write([]byte{0x00}) // trigger
	_, err = conn.Read(make([]byte, 10))
	_ = conn.Close()

	if err == nil {
		t.Skip("ECONNREFUSED is not set by system")
	}

	var ne net.Error
	if !errors.As(netError(err), &ne) {
		t.Fatalf("netError must return net.Error")
	}

	if ne.Timeout() {
		t.Errorf("%v must not be timeout error", err)
	}
	if !ne.Temporary() { //nolint:staticcheck
		t.Errorf("%v must be temporary error", err)
	}
}
