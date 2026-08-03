// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"time"

	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// PostHandshake is the state machine for DTLS 1.3 post-handshake state.

// UpdateKeys()
// |
// v
// +---------------------------------------------------------------+
// |                    fsm13: StateFinished  / PostHandshake      |
// |                                                               |
// |  incoming control event     outgoing request      RTO timer   |
// |  ----------------------     ----------------      ---------   |
// |  NewSessionTicket           Send KeyUpdate        retransmit  |
// |  KeyUpdate                  Send ticket           active      |
// |  ACK                        response KeyUpdate    flight      |
// |                                                               |
// |                  one active outbound flight                   |
// |                  plus an outbound queue                       |
// +---------------------------------------------------------------+
//                              |                              |
//                              v                              v
//                       record/key state                writePackets()

type postHandshakeCategory uint8

// rfc9147 section 5.8.4
// https://datatracker.ietf.org/doc/html/rfc9147#section-5.8.4
const (
	postHandshakeNewSessionTicket     postHandshakeCategory = iota //nolint:unused
	postHandshakeKeyUpdate                                         //nolint:unused
	postHandshakeNewConnectionID                                   //nolint:unused
	postHandshakeRequestConnectionID                               //nolint:unused
	postHandshakeClientAuthentication                              //nolint:unused
)

type postHandshakeFlightID struct {
	Category        postHandshakeCategory
	MessageSequence uint16
}

type postHandshakeFragment struct {
	MessageSequence uint16
	Offset          uint32
	Length          uint32
}

type postHandshakeRecord struct {
	Flight    postHandshakeFlightID
	Fragments []postHandshakeFragment
}

type reliablePostHandshakeFlight struct {
	ID postHandshakeFlightID

	// Constructed once. Retransmissions will reuse these messages and their
	// message_seq values.
	Packets []*dtlsflight.Packet

	// All retransmissions will use this epoch/key generation.
	Epoch uint16

	// Logical fragments not yet acknowledged.
	PendingFragments map[postHandshakeFragment]struct{}

	// Every record number used by the transmission and all
	// retransmissions.
	SentRecords map[protocol.RecordNumber]struct{}

	RetransmitInterval time.Duration
	NextRetransmit     time.Time

	// non-nil for application commands that wait for completion.
	Result chan error
}

type postHandshakeCommandKind uint8

const (
	commandSendNewSessionTicket postHandshakeCommandKind = iota
	commandSendKeyUpdate
	commandSendNewConnectionID
	commandSendRequestConnectionID
)

type keyUpdateCommand13 struct {
	Request handshake.KeyUpdateRequest

	// True when this is a protocol-required response to an incoming
	// update_requested KeyUpdate.
	RequiredResponse bool
}

type postHandshakeCommand struct {
	Kind postHandshakeCommandKind

	KeyUpdate keyUpdateCommand13

	// Always buffered with capacity one.
	Result chan error
}

type postHandshake struct {
	initialized bool

	commands chan postHandshakeCommand
	queue    []postHandshakeCommand

	flights map[postHandshakeFlightID]*reliablePostHandshakeFlight

	// Reverse lookup for received ACK record numbers.
	recordIndex map[protocol.RecordNumber]postHandshakeRecord

	initialRetransmitInterval time.Duration
}

func newPostHandshake(
	initialRetransmitInterval time.Duration,
) *postHandshake {
	return &postHandshake{
		commands: make(chan postHandshakeCommand),

		flights: make(
			map[postHandshakeFlightID]*reliablePostHandshakeFlight,
		),
		recordIndex: make(
			map[protocol.RecordNumber]postHandshakeRecord,
		),

		initialRetransmitInterval: initialRetransmitInterval,
	}
}

func (p *postHandshake) initialize(isClient bool) {
	if p.initialized {
		return
	}
	p.initialized = true

	if !isClient {
		p.queue = append(
			p.queue,
			postHandshakeCommand{
				Kind: commandSendNewSessionTicket,
			},
		)
	}
}
