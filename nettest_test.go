// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package dtls

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/transport/v4/test"
	"golang.org/x/net/nettest"
)

const nettestBasicIOCloseDelay = 50 * time.Millisecond

func TestNetTest(t *testing.T) {
	lim := test.TimeOut(time.Minute*1 + time.Second*10)
	defer lim.Stop()

	var makePipeCalls atomic.Int32

	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
		c1, c2, err = pipeMemory()
		if err != nil {
			return nil, nil, nil, err
		}

		if makePipeCalls.Add(1) == 1 {
			c1 = &delayedCloseConn{Conn: c1, delay: nettestBasicIOCloseDelay}
			c2 = &delayedCloseConn{Conn: c2, delay: nettestBasicIOCloseDelay}
		}

		var stopOnce sync.Once
		stop = func() {
			stopOnce.Do(func() {
				_ = c1.Close()
				_ = c2.Close()
			})
		}

		return c1, c2, stop, nil
	})
}

type delayedCloseConn struct {
	net.Conn
	delay time.Duration

	closeOnce sync.Once
	closeErr  error
}

func (c *delayedCloseConn) Close() error {
	c.closeOnce.Do(func() {
		time.Sleep(c.delay)
		c.closeErr = c.Conn.Close()
	})

	return c.closeErr
}
