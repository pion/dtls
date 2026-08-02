// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import "sync"

// Establishment represents the one-way transition from handshaking to an
// established DTLS connection.
//
// It is separate from FSM.Done() because the FSM remains active after
// establishment to handle final-flight retransmissions.
type Establishment struct {
	once sync.Once
	done chan struct{}
}

// NewEstablishment creates an unestablished handshake lifecycle signal.
func NewEstablishment() *Establishment {
	return &Establishment{done: make(chan struct{})}
}

// Done is closed when the handshake first becomes established.
func (e *Establishment) Done() <-chan struct{} {
	return e.done
}

// Established reports whether the handshake has become established.
func (e *Establishment) Established() bool {
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}

// mark the handshake as established.
func (e *Establishment) mark() {
	e.once.Do(func() {
		close(e.done)
	})
}
