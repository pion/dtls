// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func flight4bParse(
	_ context.Context,
	_ flightConn,
	state *dtlsstate.State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *alert.Alert, error) {
	_, msgs, ok := cache.fullPullMap(state.HandshakeRecvSequence, state.CipherSuite,
		handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, true, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	var finished *handshake.MessageFinished
	if finished, ok = msgs[handshake.TypeFinished].(*handshake.MessageFinished); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	plainText := cache.pullAndMerge(
		handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
		handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, false},
		handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, false, false},
	)

	expectedVerifyData, err := prf.VerifyDataClient(state.MasterSecret, plainText, state.CipherSuite.HashFunc())
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if !bytes.Equal(expectedVerifyData, finished.VerifyData) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrVerifyDataMismatch
	}

	// Other party may re-transmit the last flight. Keep state to be flight4b.
	return flight4b, nil, nil
}

//nolint:cyclop
func flight4bGenerate(
	_ flightConn,
	state *dtlsstate.State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *alert.Alert, error) {
	var pkts []*packet

	extensions := []extension.Extension{&extension.RenegotiationInfo{
		RenegotiatedConnection: 0,
	}}
	if (cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		cfg.extendedMasterSecret == RequireExtendedMasterSecret) && state.ExtendedMasterSecret {
		extensions = append(extensions, &extension.UseExtendedMasterSecret{
			Supported: true,
		})
	}
	if state.GetSRTPProtectionProfile() != 0 {
		extensions = append(extensions, &extension.UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{state.GetSRTPProtectionProfile()},
			MasterKeyIdentifier: cfg.localSRTPMasterKeyIdentifier,
		})
	}

	selectedProto, err := extension.ALPNProtocolSelection(cfg.supportedProtocols, state.PeerSupportedProtocols)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.NoApplicationProtocol}, err
	}
	if selectedProto != "" {
		extensions = append(extensions, &extension.ALPN{
			ProtocolNameList: []string{selectedProto},
		})
		state.NegotiatedProtocol = selectedProto
	}

	cipherSuiteID := uint16(state.CipherSuite.ID())
	var serverHello handshake.Handshake

	serverHelloMessage := &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		Random:            state.LocalRandom,
		SessionID:         state.SessionID,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: defaultCompressionMethods()[0],
		Extensions:        extensions,
	}

	if cfg.serverHelloMessageHook != nil {
		serverHello = handshake.Handshake{Message: cfg.serverHelloMessageHook(*serverHelloMessage)}
	} else {
		serverHello = handshake.Handshake{Message: serverHelloMessage}
	}

	serverHello.Header.MessageSequence = uint16(state.HandshakeSendSequence) //nolint:gosec // G115

	if len(state.LocalVerifyData) == 0 {
		plainText := cache.pullAndMerge(
			handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
		)
		raw, err := serverHello.Marshal()
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		plainText = append(plainText, raw...)

		state.LocalVerifyData, err = prf.VerifyDataServer(state.MasterSecret, plainText, state.CipherSuite.HashFunc())
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	pkts = append(pkts,
		&packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &serverHello,
			},
		},
		&packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &protocol.ChangeCipherSpec{},
			},
		},
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
		},
	)

	return pkts, nil, nil
}
