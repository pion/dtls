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
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func flight6Parse(
	_ context.Context,
	_ dtlsflight.Conn,
	state *dtlsstate.State,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (dtlsflight.Flight12, *alert.Alert, error) {
	_, msgs, ok := cache.FullPullMap(state.HandshakeRecvSequence-1, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeFinished, Epoch: cfg.InitialEpoch + 1, IsClient: true, Optional: false}, //nolint:lll
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if _, ok = msgs[handshake.TypeFinished].(*handshake.MessageFinished); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	// Other party may re-transmit the last  Keep state to be Flight6.
	return dtlsflight.Flight6, nil, nil
}

func flight6Generate(
	_ dtlsflight.Conn,
	state *dtlsstate.State,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	var pkts []*dtlsflight.Packet

	pkts = append(pkts,
		&dtlsflight.Packet{
			Record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &protocol.ChangeCipherSpec{},
			},
		})

	if len(state.LocalVerifyData) == 0 {
		//nolint:dupl
		plainText := cache.PullAndMerge(
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},         //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},        //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificate, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},        //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerKeyExchange, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},  //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificateRequest, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false}, //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHelloDone, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},    //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificate, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},         //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientKeyExchange, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},   //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificateVerify, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},   //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeFinished, Epoch: cfg.InitialEpoch + 1, IsClient: true, Optional: false},        //nolint:lll
		)

		var err error
		state.LocalVerifyData, err = prf.VerifyDataServer(state.MasterSecret, plainText, state.CipherSuite.HashFunc())
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	pkts = append(pkts,
		&dtlsflight.Packet{
			Record: &recordlayer.RecordLayer{
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
			ShouldWrapCID:            len(state.RemoteConnectionID) > 0,
			ShouldEncrypt:            true,
			ResetLocalSequenceNumber: true,
		},
	)

	return pkts, nil, nil
}
