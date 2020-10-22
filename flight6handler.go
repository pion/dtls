package dtls

import (
	"context"
)

func flight6Parse(ctx context.Context, c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) (flightVal, *alert, error) {
	_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence-1,
		handshakeCachePullRule{handshakeTypeFinished, cfg.initialEpoch + 1, true, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if _, ok = msgs[handshakeTypeFinished].(*handshakeMessageFinished); !ok {
		return 0, &alert{alertLevelFatal, alertInternalError}, nil
	}

	// Other party retransmitted the last flight.
	return flight6, nil, nil
}

func flight6Generate(c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) ([]*packet, *alert, error) {
	var pkts []*packet

	pkts = append(pkts,
		&packet{
			record: &RecordLayer{
				RecordLayerHeader: RecordLayerHeader{
					ProtocolVersion: ProtocolVersion1_2,
				},
				Content: &changeCipherSpec{},
			},
		})

	if len(state.localVerifyData) == 0 {
		plainText := cache.pullAndMerge(
			handshakeCachePullRule{handshakeTypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshakeTypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakeTypeCertificate, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakeTypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakeTypeCertificateRequest, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakeTypeServerHelloDone, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshakeTypeCertificate, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshakeTypeClientKeyExchange, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshakeTypeCertificateVerify, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshakeTypeFinished, cfg.initialEpoch + 1, true, false},
		)

		var err error
		state.localVerifyData, err = prfVerifyDataServer(state.masterSecret, plainText, state.CipherSuite.HashFunc())
		if err != nil {
			return nil, &alert{alertLevelFatal, alertInternalError}, err
		}
	}

	pkts = append(pkts,
		&packet{
			record: &RecordLayer{
				RecordLayerHeader: RecordLayerHeader{
					ProtocolVersion: ProtocolVersion1_2,
					Epoch:           1,
				},
				Content: &handshake{
					handshakeMessage: &handshakeMessageFinished{
						verifyData: state.localVerifyData,
					},
				},
			},
			shouldEncrypt:            true,
			resetLocalSequenceNumber: true,
		},
	)
	return pkts, nil, nil
}
