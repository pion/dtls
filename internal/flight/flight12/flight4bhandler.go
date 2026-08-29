// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"bytes"
	"context"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

func flight4bParse(_ context.Context, _ dtlsflight.Conn, state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) (Flight, *alert.Alert, error) {
	pull := cache.FullPullMapItems(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeFinished, Epoch: cfg.InitialEpoch + 1, IsClient: true, Optional: false},
	)
	if pull.Err != nil {
		return 0, nil, pull.Err
	}
	if !pull.Ready {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	finished, ok := pull.Messages[handshake.TypeFinished].(*handshake.MessageFinished)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	plainText := cache.PullAndMerge(
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeFinished, Epoch: cfg.InitialEpoch + 1, IsClient: false, Optional: false},
	)

	expectedVerifyData, err := prf.VerifyDataClient(state.MasterSecret, plainText, state.CipherSuite.HashFunc())
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if !bytes.Equal(expectedVerifyData, finished.VerifyData) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrVerifyDataMismatch
	}

	// Other party may re-transmit the last  Keep state to be Flight4b.
	return Flight4b, nil, nil
}

//nolint:cyclop
func flight4bGenerate(_ dtlsflight.Conn, state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	var pkts []*dtlsflight.Outbound
	offer := state.RemoteClientHelloSnapshots.Current()
	srtpSelection, err := negotiation.NegotiateSRTP(offer, cfg.LocalSRTPProtectionProfiles, cfg.LocalSRTPMasterKeyIdentifier)
	if err != nil {
		return nil, nil, err
	}

	extensions := []extension.Value{}
	if state.RemoteSupportsRenegotiation {
		extensions = append(extensions, &extension12.RenegotiationInfo{
			RenegotiatedConnection: 0,
		})
	}
	if (cfg.ExtendedMasterSecret == dtlsconfig.RequestExtendedMasterSecret || cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret) && state.ExtendedMasterSecret {
		extensions = append(extensions, &extension12.ExtendedMasterSecret{})
	}
	extensions = appendSRTPSelection(extensions, srtpSelection)

	selectedProto, err := extension.ALPNProtocolSelection(cfg.SupportedProtocols, state.PeerSupportedProtocols)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.NoApplicationProtocol}, err
	}
	if selectedProto != "" {
		extensions = append(extensions, &extension.ALPNSelection{Protocol: selectedProto})
		state.NegotiatedProtocol = selectedProto
	}
	if cid := serverCIDExtension(state, cfg, offer); cid != nil {
		extensions = dtlsflight.AppendConnectionIDExtensions(extensions, cid.CID, cfg.EnableRRC && offer.Offered(extension.TypeReturnRoutabilityCheck))
	}

	cipherSuiteID := uint16(state.CipherSuite.ID())
	serverHelloMessage := &handshake.MessageServerHello{Version: protocol.Version1_2, Random: state.LocalRandom, SessionID: state.SessionID, CipherSuiteID: &cipherSuiteID, CompressionMethod: dtlsflight.DefaultCompressionMethods()[0], Extensions: extensions}

	serverHelloMessage, err = dtlsflight.FinalizeServerHello(serverHelloMessage, cfg.ServerHelloMessageHook, offer, cfg.EnableRRC)
	if err != nil {
		return nil, nil, err
	}
	if err = validateServerSRTP(offer, serverHelloMessage.Extensions, cfg.LocalSRTPProtectionProfiles, srtpSelection); err != nil {
		return nil, nil, err
	}
	decision := negotiation.DecideConnectionID(offer, serverHelloMessage.Extensions)
	serverHello := handshake.Handshake{Message: serverHelloMessage}

	serverHello.Header.MessageSequence = uint16(state.HandshakeSendSequence) //nolint:gosec // G115

	if len(state.LocalVerifyData) == 0 {
		plainText := cache.PullAndMerge(
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},
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

	pkts = append(pkts, &dtlsflight.Outbound{Content: &serverHello}, &dtlsflight.Outbound{Content: &protocol.ChangeCipherSpec{}}, &dtlsflight.Outbound{Epoch: 1, Content: &handshake.Handshake{Message: &handshake.MessageFinished{VerifyData: state.LocalVerifyData}}, Protection: dtlsflight.ProtectionCiphertext})
	state.CommitNegotiatedExtensions(decision)
	dtlsflight.CommitSRTP(state.Common, srtpSelection)

	return pkts, nil, nil
}
