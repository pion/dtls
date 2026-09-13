// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
)

var (
	errMessageMismatch        = errors.New("messages mismatch")
	errInvalidConnectionState = errors.New("failed to get connection state")
)

func TestResumeClient(t *testing.T) {
	DoTestResume(t, resumeClient, resumeServer)
}

func TestResumeServer(t *testing.T) {
	DoTestResume(t, resumeServer, resumeClient)
}

func resumeClient(conn net.PacketConn, rAddr net.Addr, opts []Option) (*Conn, error) {
	clientOpts := make([]ClientOption, len(opts))
	for i, opt := range opts {
		clientOpts[i] = opt
	}

	return Client(conn, rAddr, clientOpts...)
}

func resumeServer(conn net.PacketConn, rAddr net.Addr, opts []Option) (*Conn, error) {
	serverOpts := make([]ServerOption, len(opts))
	for i, opt := range opts {
		serverOpts[i] = opt
	}

	return Server(conn, rAddr, serverOpts...)
}

func fatal(t *testing.T, errChan chan error, err error) {
	t.Helper()

	close(errChan)
	assert.NoError(t, err)
}

//nolint:cyclop
func DoTestResume(
	t *testing.T,
	newLocal,
	newRemote func(net.PacketConn, net.Addr, []Option) (*Conn, error),
) {
	t.Helper()

	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	// Generate connections
	localConn1, rc1 := packetPipe()
	localConn2, rc2 := packetPipe()
	remoteConn := &backupConn{}
	remoteConn.curr.Store(rc1)

	// Launch remote in another goroutine
	errChan := make(chan error, 1)
	defer func() {
		err = <-errChan
		assert.NoError(t, err)
	}()
	opts := []Option{WithCertificates(certificate), WithInsecureSkipVerify(true), WithExtendedMasterSecret(RequireExtendedMasterSecret)}
	go func() {
		var remote *Conn
		var errR error
		remote, errR = newRemote(remoteConn, rc1.RemoteAddr(), opts)
		if errR != nil {
			errChan <- errR
		}

		// Loop of read write
		for range 2 {
			recv := make([]byte, 1024)
			var n int
			n, errR = remote.Read(recv)
			assert.NoError(t, errR)

			if _, errR = remote.Write(recv[:n]); errR != nil {
				errChan <- errR
			}
		}
		errChan <- nil
	}()

	var local *Conn
	local, err = newLocal(localConn1, localConn1.RemoteAddr(), opts)
	if err != nil {
		fatal(t, errChan, err)
	}
	defer func() {
		_ = local.Close()
	}()

	// Test write and read
	message := []byte("Hello")
	if _, err = local.Write(message); err != nil {
		fatal(t, errChan, err)
	}

	recv := make([]byte, 1024)
	var n int
	n, err = local.Read(recv)
	if err != nil {
		fatal(t, errChan, err)
	}

	if !bytes.Equal(message, recv[:n]) {
		fatal(t, errChan, fmt.Errorf("%w: %s != %s", errMessageMismatch, message, recv[:n]))
	}

	if err = localConn1.Close(); err != nil {
		fatal(t, errChan, err)
	}
	// Select the replacement transport, then wake any read on the old pipe.
	remoteConn.curr.Store(rc2)
	if err = rc1.Close(); err != nil {
		fatal(t, errChan, err)
	}

	// Serialize and deserialize state
	state, ok := local.ConnectionState()
	if !ok {
		fatal(t, errChan, errInvalidConnectionState)
	}
	var b []byte
	b, err = state.MarshalBinary()
	if err != nil {
		fatal(t, errChan, err)
	}
	deserialized := &State{}
	if err = deserialized.UnmarshalBinary(b); err != nil {
		fatal(t, errChan, err)
	}

	// Resume dtls connection
	var resumed net.Conn
	resumed, err = Resume(
		deserialized,
		localConn2,
		localConn2.RemoteAddr(),
		opts...,
	)
	if err != nil {
		fatal(t, errChan, err)
	}
	defer func() {
		_ = resumed.Close()
	}()

	// Test write and read on resumed connection
	if _, err = resumed.Write(message); err != nil {
		fatal(t, errChan, err)
	}

	recv = make([]byte, 1024)
	n, err = resumed.Read(recv)
	if err != nil {
		fatal(t, errChan, err)
	}

	if !bytes.Equal(message, recv[:n]) {
		fatal(t, errChan, fmt.Errorf("%w: %s != %s", errMessageMismatch, message, recv[:n]))
	}
}

type backupConn struct {
	curr atomic.Pointer[packetTestConn]
}

func (b *backupConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	curr := b.curr.Load()
	n, addr, err = curr.ReadFrom(data)
	if err != nil && curr != b.curr.Load() {
		return b.ReadFrom(data)
	}

	return n, addr, err
}

func (b *backupConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	return b.curr.Load().WriteTo(data, addr)
}

func (b *backupConn) Close() error {
	return nil
}

func (b *backupConn) LocalAddr() net.Addr {
	return b.curr.Load().LocalAddr()
}

func (b *backupConn) SetDeadline(deadline time.Time) error {
	return b.curr.Load().SetDeadline(deadline)
}

func (b *backupConn) SetReadDeadline(deadline time.Time) error {
	return b.curr.Load().SetReadDeadline(deadline)
}

func (b *backupConn) SetWriteDeadline(deadline time.Time) error {
	return b.curr.Load().SetWriteDeadline(deadline)
}
