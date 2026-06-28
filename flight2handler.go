// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func flight2Parse(
	ctx context.Context,
	c flightConn,
	state *dtlsstate.State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *alert.Alert, error) {
	seq, msgs, ok := cache.fullPullMap(state.HandshakeRecvSequence, state.CipherSuite,
		handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
	)
	if !ok {
		// Client may retransmit the first ClientHello when HelloVerifyRequest is dropped.
		// Parse as flight 0 in this case.
		return flight0Parse(ctx, c, state, cache, cfg)
	}
	state.HandshakeRecvSequence = seq

	var clientHello *handshake.MessageClientHello

	// Validate type
	if clientHello, ok = msgs[handshake.TypeClientHello].(*handshake.MessageClientHello); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if !clientHello.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
			dtlserrors.ErrUnsupportedProtocolVersion
	}

	if len(clientHello.Cookie) == 0 {
		return 0, nil, nil
	}
	if !bytes.Equal(state.Cookie, clientHello.Cookie) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.AccessDenied}, dtlserrors.ErrCookieMismatch
	}

	return flight4, nil, nil
}

func flight2Generate(
	_ flightConn,
	state *dtlsstate.State,
	_ *handshakeCache,
	_ *handshakeConfig,
) ([]*packet, *alert.Alert, error) {
	state.HandshakeSendSequence = 0

	return []*packet{
		{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageHelloVerifyRequest{
						Version: protocol.Version1_2,
						Cookie:  state.Cookie,
					},
				},
			},
		},
	}, nil, nil
}
