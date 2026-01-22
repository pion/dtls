// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build aix || darwin || dragonfly || freebsd || linux || nacl || nacljs || netbsd || openbsd || solaris || windows
// +build aix darwin dragonfly freebsd linux nacl nacljs netbsd openbsd solaris windows

// For systems having syscall.Errno.
// The build target must be same as errors_errno.go.

package dtls

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestErrorsTemporary(t *testing.T) {
	// Allocate a UDP port no one is listening on.
	addrListen, err := net.ResolveUDPAddr("udp", "localhost:0")
	assert.NoError(t, err)

	listener, err := net.ListenUDP("udp", addrListen)
	assert.NoError(t, err)

	raddr, ok := listener.LocalAddr().(*net.UDPAddr)
	assert.True(t, ok)
	assert.NoError(t, listener.Close())

	// Server is not listening.
	conn, errDial := net.DialUDP("udp", nil, raddr)
	assert.NoError(t, errDial)

	_, _ = conn.Write([]byte{0x00}) // trigger
	// Avoid indefinite blocking on platforms that don't surface ICMP errors reliably - Windows :)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 10))
	_ = conn.Close()

	if err == nil {
		t.Skip("ECONNREFUSED is not set by system")
	}

	var ne net.Error
	assert.ErrorAs(t, netError(err), &ne)

	if ne.Timeout() {
		t.Skip("timed out waiting for ICMP error; skipping on this platform")
	}

	assert.False(t, ne.Timeout())
	assert.True(t, ne.Temporary()) //nolint:staticcheck
}
