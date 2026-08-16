// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight

import (
	"context"
	"crypto"

	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

type Conn interface {
	HandleQueuedPackets(context.Context) error
	SessionKey() []byte
}

type Packet struct {
	Record         *recordlayer.RecordLayer
	ShouldEncrypt  bool
	ShouldWrapCID  bool
	ShouldTrackACK bool
	// HandshakeFragmentOffsets limits a retransmission to offset:length pairs.
	HandshakeFragmentOffsets map[uint32]uint32
	ResetLocalSequenceNumber bool

	// CertificateVerifySigner is local-only metadata used to populate an
	// outbound CertificateVerify after the handshake messages have been committed.
	CertificateVerifySigner crypto.Signer
}

type HandshakeCacheItem struct {
	Typ             handshake.Type
	IsClient        bool
	Epoch           uint16
	MessageSequence uint16
	Data            []byte

	parsed        *handshake.Handshake
	decodeContext handshakeCacheDecodeContext
	hasDecoded    bool
}

// DecodedHandshakeCacheItem retains the original cache bytes for the
// transcript and the single parsed representation used by handshake logic.
type DecodedHandshakeCacheItem struct {
	Raw    *HandshakeCacheItem
	Parsed *handshake.Handshake
}

// HandshakeCachePullResult distinguishes an incomplete flight from a complete
// malformed message. Err is non-nil only when a selected complete message
// could not be decoded or failed cache/header validation.
type HandshakeCachePullResult struct {
	NextSequence int
	Messages     map[handshake.Type]handshake.Message
	Items        []DecodedHandshakeCacheItem
	Ready        bool
	// Err always wraps an *alert.Alert.
	Err error
}

// HandshakeCacheItemPullResult is an ordered cache selection before message
// payloads are decoded. Items is aligned with the requested pull rules.
type HandshakeCacheItemPullResult struct {
	NextSequence int
	Items        []*HandshakeCacheItem
	Ready        bool
	// Err always wraps an *alert.Alert.
	Err error
}

type HandshakeCachePullRule struct {
	Typ      handshake.Type
	Epoch    uint16
	IsClient bool
	Optional bool
}
