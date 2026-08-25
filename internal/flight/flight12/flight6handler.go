// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"context"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

func flight6Parse(
	_ context.Context,
	_ dtlsflight.Conn,
	state *dtlsstate.State12,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (Flight, *alert.Alert, error) {
	pull := cache.FullPullMapItems(state.HandshakeRecvSequence-1, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeFinished, Epoch: cfg.InitialEpoch + 1, IsClient: true, Optional: false}, //nolint:lll
	)
	if pull.Err != nil {
		return 0, nil, pull.Err
	}
	if !pull.Ready {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if _, ok := pull.Messages[handshake.TypeFinished].(*handshake.MessageFinished); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	// Other party may re-transmit the last  Keep state to be Flight6.
	return Flight6, nil, nil
}

func flight6Generate(
	_ dtlsflight.Conn,
	state *dtlsstate.State12,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	var pkts []*dtlsflight.Outbound

	pkts = append(pkts,
		&dtlsflight.Outbound{
			Content: &protocol.ChangeCipherSpec{},
		})

	if len(state.LocalVerifyData) == 0 {
		plainText := cache.PullAndMerge(handshakeRulesThroughClientFinished(cfg.InitialEpoch)...)

		var err error
		state.LocalVerifyData, err = prf.VerifyDataServer(state.MasterSecret, plainText, state.CipherSuite.HashFunc())
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	pkts = append(pkts,
		&dtlsflight.Outbound{
			Epoch: 1,
			Content: &handshake.Handshake{
				Message: &handshake.MessageFinished{
					VerifyData: state.LocalVerifyData,
				},
			},
			Protection: dtlsflight.ProtectionCiphertext,
		},
	)

	return pkts, nil, nil
}
