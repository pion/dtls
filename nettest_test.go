// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package dtls

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/transport/v4/test"
	"golang.org/x/net/nettest"
)

// closeOnceConn wraps a net.Conn to make Close() idempotent,
// returning nil on subsequent calls instead of ErrConnClosed.
type closeOnceConn struct {
	net.Conn
	closeOnce sync.Once
	closeErr  error
}

func (c *closeOnceConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
	})

	return c.closeErr
}

func TestNetTest(t *testing.T) {
	lim := test.TimeOut(time.Minute*1 + time.Second*10)
	defer lim.Stop()

	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
		c1, c2, err = pipeMemory()
		if err != nil {
			return nil, nil, nil, err
		}

		// Wrap connections to handle ErrConnClosed gracefully
		c1Wrapper := &closeOnceConn{Conn: c1}
		c2Wrapper := &closeOnceConn{Conn: c2}

		stop = func() {
			_ = c1Wrapper.Close()
			_ = c2Wrapper.Close()
		}

		return c1Wrapper, c2Wrapper, stop, nil
	})
}
