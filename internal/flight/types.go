// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight

import (
	"context"

	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

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
