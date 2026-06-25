// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"bytes"
	"context"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func flight2Parse(
	ctx context.Context,
	conn dtlsflight.Conn,
	state *dtlsstate.State,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (dtlsflight.Flight12, *alert.Alert, error) {
	seq, msgs, ok := cache.FullPullMap(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false}, //nolint:lll
	)
	if !ok {
		// Client may retransmit the first ClientHello when HelloVerifyRequest is dropped.
		// Parse as flight 0 in this case.
		return flight0Parse(ctx, conn, state, cache, cfg)
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

	return dtlsflight.Flight4, nil, nil
}

func flight2Generate(
	_ dtlsflight.Conn,
	state *dtlsstate.State,
	_ *dtlsflight.Cache,
	_ *dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	state.HandshakeSendSequence = 0

	return []*dtlsflight.Packet{
		{
			Record: &recordlayer.RecordLayer{
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
