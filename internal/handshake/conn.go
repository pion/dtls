// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"

	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

// RecvHandshakeState signals that a handshake packet has been received.
type RecvHandshakeState struct {
	Done         chan struct{}
	IsRetransmit bool
}

// FSM is the common DTLS handshake FSM interface.
type FSM interface {
	Done() <-chan struct{}
	Run(ctx context.Context, conn Conn, initialState State) error
}

// Conn is the connection surface required by the DTLS handshake FSMs.
type Conn interface {
	dtlsflight.Conn
	Notify(ctx context.Context, level alert.Level, desc alert.Description) error
	WritePackets(context.Context, []*dtlsflight.Packet) error
	RecvHandshake() <-chan RecvHandshakeState
	SetLocalEpoch(epoch uint16)
}

func sideString(isClient bool) string {
	if isClient {
		return "client"
	}

	return "server"
}
