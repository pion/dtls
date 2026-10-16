// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"context"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

func flight2Parse(_ context.Context, _ dtlsflight.Conn, state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) (Flight, *alert.Alert, error) {
	pull := cache.FullPullMapItems(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},
	)
	if pull.Err != nil {
		return 0, nil, pull.Err
	}
	if !pull.Ready {
		// Only a repeated ClientHello makes the FSM resend the cookie challenge.
		return 0, nil, nil
	}
	state.HandshakeRecvSequence = pull.NextSequence

	// Validate type
	clientHello, ok := pull.Messages[handshake.TypeClientHello].(*handshake.MessageClientHello)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if clientHello.Version != protocol.Version1_2 {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlserrors.ErrUnsupportedProtocolVersion
	}

	snapshots := state.RemoteClientHelloSnapshots
	if err := snapshots.RecordWire(pull.Items[0].Raw.Data); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
	}
	if err := negotiation.ValidateHelloVerifyRequestResponse(snapshots.Initial(), snapshots.Current(), state.Cookie); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
	}
	state.RemoteClientHelloSnapshots = snapshots

	return negotiateClientHello(clientHello, state, cfg, Flight4)
}

func flight2Generate(_ dtlsflight.Conn, state *dtlsstate.State12, _ *dtlsflight.Cache, _ *dtlsconfig.HandshakeConfig) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	state.HandshakeSendSequence = 0

	return []*dtlsflight.Outbound{{Content: &handshake.Handshake{Message: &handshake.MessageHelloVerifyRequest{Version: protocol.Version1_2, Cookie: state.Cookie}}}}, nil, nil
}
