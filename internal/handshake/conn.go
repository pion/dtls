// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"

	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

// RecvHandshakeState signals that a handshake packet has been received.
type RecvHandshakeState struct {
	Done chan struct{}
	// HasHandshake distinguishes an ACK-only event from a handshake event.
	HasHandshake bool
	IsRetransmit bool
	// ACK messages received from the peer.
	ACKs []protocol.ACK
	// Protected handshake records that should be acknowledged.
	RecordsToACK []protocol.RecordNumber
}

// ACKResult is the record-layer progress caused by a received ACK.
type ACKResult struct {
	Empty    bool
	Messages []MessageACKProgress
}

// WriteResult identifies tracked handshake records emitted by one write.
type WriteResult struct {
	TrackedRecords []SentHandshakeRecord
}

type SentHandshakeRecord struct {
	Number    protocol.RecordNumber
	Fragments []SentHandshakeFragment
}

type SentHandshakeFragment struct {
	MessageSequence uint16
	Offset          uint32
	Length          uint32
}

type MessageACKProgress struct {
	MessageSequence uint16
	Changed         bool
	Complete        bool
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
	WritePackets(context.Context, []*dtlsflight.Outbound) (*WriteResult, error)
	// WriteHandshakePackets writes packets that belong to the handshake. It is
	// separate from WritePackets so the connection can offer only those to a
	// handshake packet interceptor.
	WriteHandshakePackets(context.Context, []*dtlsflight.Outbound) (*WriteResult, error)
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

	_, err := conn.WriteHandshakePackets(ctx, []*dtlsflight.Outbound{{
		Epoch:      epoch,
		Content:    &protocol.ACK{Records: records},
		Protection: dtlsflight.ProtectionCiphertext,
	}})

	return err
}
