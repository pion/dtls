// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"context"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/internal/negotiation"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func flight2Parse( //nolint:cyclop
	_ context.Context,
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) (Flight, *alert.Alert, error) {
	pull := flightCtx.cache.FullPullMapItems(
		flightCtx.state.HandshakeRecvSequence, flightCtx.state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: flightCtx.cfg.InitialEpoch, IsClient: true, Optional: false}, //nolint:lll
	)
	if pull.Err != nil {
		return 0, nil, pull.Err
	}
	if !pull.Ready {
		return 0, nil, nil
	}

	clientHello, ok := pull.Messages[handshake.TypeClientHello].(*handshake.MessageClientHello)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if !clientHello.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
			dtlserrors.ErrUnsupportedProtocolVersion
	}
	snapshots := flightCtx.state.RemoteClientHelloSnapshots
	if err := snapshots.RecordWire(pull.Items[0].Raw.Data); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
	}
	if err := negotiation.ValidateClientHelloRetry(
		snapshots.Initial(), snapshots.Current(), flightCtx.state.HelloRetryRequest,
	); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
	}

	if failure := processClientHelloExtensions(flightCtx.state, clientHello); failure != nil {
		return 0, failure.alert, failure.err
	}
	if failure := generateClientKeyShareSecret(flightCtx.state, flightCtx.cfg); failure != nil {
		return 0, failure.alert, failure.err
	}
	if failure := flightCtx.handleInboundHandshake(pull.Items); failure != nil {
		return 0, failure.alert, failure.err
	}
	flightCtx.state.RemoteClientHelloSnapshots = snapshots
	flightCtx.state.HandshakeRecvSequence = pull.NextSequence

	return Flight4, nil, nil
}

func flight2Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	flightCtx.state.HandshakeSendSequence = 0
	if flightCtx.state.CipherSuite == nil {
		return nil, nil, dtlserrors.ErrCipherSuiteUnset
	}

	random := handshake.Random{}
	random.UnmarshalFixed([32]byte(handshake.HelloRetryRequestRandom()))

	exts := []extension.Value{}

	exts = append(exts, &extension13.SelectedVersion{
		Version: protocol.Version1_3,
	})
	cipherSuiteID := uint16(flightCtx.state.CipherSuite.ID())

	if flightCtx.state.SelectedGroup != 0 {
		// RFC 8446 Section 4.2.8 requires a client to abort with illegal_parameter
		// if an HRR selects a group for which it already supplied a key share.
		// https://www.rfc-editor.org/rfc/rfc9147.html#section-5.1
		// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8
		_, clientAlreadyOfferedShare := clientKeyShareForGroup(flightCtx.state, flightCtx.state.SelectedGroup)
		if !clientAlreadyOfferedShare {
			exts = append(exts, &extension13.RetryKeyShare{
				SelectedGroup: flightCtx.state.SelectedGroup,
			})
		}
	}

	if len(flightCtx.state.Cookie) > 0 {
		exts = append(exts, &extension13.Cookie{
			Cookie: flightCtx.state.Cookie,
		})
	}
	serverHello := &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		Random:            random,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
		Extensions:        exts,
	}
	request, err := negotiation.ValidateHelloRetryRequest(
		flightCtx.state.RemoteClientHelloSnapshots.Initial(), serverHello,
	)
	if err != nil {
		return nil, nil, err
	}
	flightCtx.state.HelloRetryRequest = request

	return []*dtlsflight.Packet{
		{
			Record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: serverHello,
				},
			},
		},
	}, nil, nil
}
