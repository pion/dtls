// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"

	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func flight5bParse(
	_ context.Context,
	_ flightConn,
	state *dtlsstate.State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *alert.Alert, error) {
	_, msgs, ok := cache.fullPullMap(state.HandshakeRecvSequence-1, state.CipherSuite,
		handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, false, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if _, ok = msgs[handshake.TypeFinished].(*handshake.MessageFinished); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	// Other party may re-transmit the last flight. Keep state to be flight5b.
	return flight5b, nil, nil
}

func flight5bGenerate(
	_ flightConn,
	state *dtlsstate.State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *alert.Alert, error) { //nolint:gocognit
	var pkts []*packet

	pkts = append(pkts,
		&packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &protocol.ChangeCipherSpec{},
			},
		})

	if len(state.LocalVerifyData) == 0 {
		plainText := cache.pullAndMerge(
			handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, false, false},
		)

		var err error
		state.LocalVerifyData, err = prf.VerifyDataClient(state.MasterSecret, plainText, state.CipherSuite.HashFunc())
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	pkts = append(pkts,
		&packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
					Epoch:   1,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageFinished{
						VerifyData: state.LocalVerifyData,
					},
				},
			},
			shouldEncrypt:            true,
			resetLocalSequenceNumber: true,
		})

	return pkts, nil, nil
}
