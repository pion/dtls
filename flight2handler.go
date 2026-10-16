// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/sha256"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func flight2Parse(
	ctx context.Context,
	c flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *alert.Alert, error) {
	seq, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence, state.cipherSuite,
		handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
	)
	if !ok {
		// Client may retransmit the first ClientHello when HelloVerifyRequest is dropped.
		// Parse as flight 0 in this case.
		return flight0Parse(ctx, c, state, cache, cfg)
	}

	var clientHello *handshake.MessageClientHello

	// Validate type
	if clientHello, ok = msgs[handshake.TypeClientHello].(*handshake.MessageClientHello); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if !clientHello.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, errUnsupportedProtocolVersion
	}

	if len(clientHello.Cookie) == 0 {
		return 0, nil, nil
	}
	if !bytes.Equal(state.cookie, clientHello.Cookie) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.AccessDenied}, errCookieMismatch
	}
	helloHash, err := clientHelloNegotiationHash(clientHello)
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
	}
	if helloHash != state.initialClientHelloHash {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, errClientHelloChanged
	}
	state.handshakeRecvSequence = seq

	return negotiateClientHello(clientHello, state, cfg, flight4)
}

// RFC 6347 section 4.2.1 requires these core parameters to stay unchanged
// across HelloVerifyRequest. Extensions are negotiated from the retry.
func clientHelloNegotiationHash(hello *handshake.MessageClientHello) ([sha256.Size]byte, error) {
	normalized := *hello
	normalized.Cookie = nil
	normalized.Extensions = nil
	raw, err := normalized.Marshal()
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	return sha256.Sum256(raw), nil
}

func flight2Generate(
	_ flightConn,
	state *State,
	_ *handshakeCache,
	_ *handshakeConfig,
) ([]*packet, *alert.Alert, error) {
	state.handshakeSendSequence = 0

	return []*packet{
		{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageHelloVerifyRequest{
						Version: protocol.Version1_2,
						Cookie:  state.cookie,
					},
				},
			},
		},
	}, nil, nil
}
