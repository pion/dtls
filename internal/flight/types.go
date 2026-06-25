// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight

import (
	"context"

	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

type Flight12 uint8

const (
	Flight0 Flight12 = iota + 1
	Flight1
	Flight2
	Flight3
	Flight4
	Flight4b
	Flight5
	Flight5b
	Flight6
)

func (f Flight12) String() string { //nolint:cyclop
	switch f {
	case Flight0:
		return "Flight 0"
	case Flight1:
		return "Flight 1"
	case Flight2:
		return "Flight 2"
	case Flight3:
		return "Flight 3"
	case Flight4:
		return "Flight 4"
	case Flight4b:
		return "Flight 4b"
	case Flight5:
		return "Flight 5"
	case Flight5b:
		return "Flight 5b"
	case Flight6:
		return "Flight 6"
	default:
		return "Invalid Flight"
	}
}

func (f Flight12) IsLastSendFlight() bool {
	return f == Flight6 || f == Flight5b
}

func (f Flight12) IsLastRecvFlight() bool {
	return f == Flight5 || f == Flight4b
}

type Flight13 uint8

const (
	Flight13_0 Flight13 = iota + 1
	Flight13_1
	Flight13_2
	Flight13_3
	_
	_
	Flight13_4
	_
	_
	_
	Flight13_5
)

func (f Flight13) String() string { //nolint:cyclop
	switch f {
	case Flight13_0:
		return "Flight13 0"
	case Flight13_1:
		return "Flight13 1"
	case Flight13_2:
		return "Flight13 2"
	case Flight13_3:
		return "Flight13 3"
	case Flight13_4:
		return "Flight13 4"
	case Flight13_5:
		return "Flight13 5"
	default:
		return "Invalid Flight"
	}
}

type Conn interface {
	HandleQueuedPackets(context.Context) error
	SessionKey() []byte
}

type Packet struct {
	Record                   *recordlayer.RecordLayer
	ShouldEncrypt            bool
	ShouldWrapCID            bool
	ResetLocalSequenceNumber bool
}

type HandshakeCacheItem struct {
	Typ             handshake.Type
	IsClient        bool
	Epoch           uint16
	MessageSequence uint16
	Data            []byte
}

type HandshakeCachePullRule struct {
	Typ      handshake.Type
	Epoch    uint16
	IsClient bool
	Optional bool
}
