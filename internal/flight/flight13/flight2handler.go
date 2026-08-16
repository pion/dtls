// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"context"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
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
	cookie := clientHelloCookie(clientHello.Extensions)

	if len(cookie) == 0 {
		return 0, nil, nil
	}
	if !bytes.Equal(flightCtx.state.Cookie, cookie) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.AccessDenied}, dtlserrors.ErrCookieMismatch
	}
	if failure := validateRepeatedClientHelloConnectionID(flightCtx.state, clientHello); failure != nil {
		return 0, failure.alert, failure.err
	}

	if failure := processClientHelloExtensions(flightCtx.state, flightCtx.cfg, clientHello); failure != nil {
		return 0, failure.alert, failure.err
	}
	if failure := generateClientKeyShareSecret(flightCtx.state, flightCtx.cfg); failure != nil {
		return 0, failure.alert, failure.err
	}
	if failure := flightCtx.handleInboundHandshake(pull.Items); failure != nil {
		return 0, failure.alert, failure.err
	}
	if err := flightCtx.state.RemoteClientHelloSnapshots.RecordWire(pull.Items[0].Raw.Data); err != nil {
		return 0, nil, err
	}
	flightCtx.state.HandshakeRecvSequence = pull.NextSequence

	return Flight4, nil, nil
}

func validateRepeatedClientHelloConnectionID(
	state *dtlsstate.State13,
	clientHello *handshake.MessageClientHello,
) *clientHelloExtensionFailure {
	remoteCID, present, duplicate := connectionIDExtension(clientHello.Extensions)
	expectedPresent := state.RemoteCIDOffered
	if duplicate || present != expectedPresent || (present && !bytes.Equal(remoteCID, state.RemoteConnectionID)) {
		return newClientHelloExtensionFailure(alert.IllegalParameter, dtlserrors.ErrInvalidClientHello)
	}

	return nil
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

	return []*dtlsflight.Packet{
		{
			Record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageServerHello{
						Version:           protocol.Version1_2,
						Random:            random,
						CipherSuiteID:     &cipherSuiteID,
						CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
						Extensions:        exts,
					},
				},
			},
		},
	}, nil, nil
}
