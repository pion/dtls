// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"

	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// RecvHandshakeState signals that a handshake packet has been received.
type RecvHandshakeState struct {
	Done         chan struct{}
	IsRetransmit bool
	Records      []protocol.RecordNumber
}

// recvHandshakeLease keeps the reader paused while an FSM transition needs
// exclusive access to the received records. Releasing the lease lets the
// reader process the next datagram.
type recvHandshakeLease struct {
	done chan struct{}
}

func (l *recvHandshakeLease) retain(state RecvHandshakeState) {
	l.release()
	l.done = state.Done
}

func (l *recvHandshakeLease) release() {
	if l.done == nil {
		return
	}

	close(l.done)
	l.done = nil
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

func sendACK(ctx context.Context, conn Conn, epoch uint16, records []protocol.RecordNumber) error {
	if len(records) == 0 {
		return nil
	}

	return conn.WritePackets(ctx, []*dtlsflight.Packet{{
		Record: &recordlayer.RecordLayer{
			Header:  recordlayer.Header{Version: protocol.Version1_2, Epoch: epoch},
			Content: &protocol.ACK{Records: records},
		},
		ShouldEncrypt: true,
	}})
}
