// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"context"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func flight2Parse(
	_ context.Context,
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) (Flight, *alert.Alert, error) {
	seq, msgs, items, ok := flightCtx.cache.FullPullMapItems(
		flightCtx.state.HandshakeRecvSequence, flightCtx.state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: flightCtx.cfg.InitialEpoch, IsClient: true, Optional: false}, //nolint:lll
	)
	if !ok {
		return 0, nil, nil
	}

	clientHello, ok := msgs[handshake.TypeClientHello].(*handshake.MessageClientHello)
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

	if failure := processClientHelloExtensions(flightCtx.state, flightCtx.cfg, clientHello); failure != nil {
		return 0, failure.alert, failure.err
	}
	if failure := generateClientKeyShareSecret(flightCtx.state, flightCtx.cfg); failure != nil {
		return 0, failure.alert, failure.err
	}
	if flightCtx.inboundHandshakeHandler != nil {
		if err := flightCtx.inboundHandshakeHandler(flightCtx.state.CipherSuite, items); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}
	flightCtx.state.HandshakeRecvSequence = seq

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

	exts := []extension.Extension{}

	exts = append(exts, &extension.SupportedVersions{
		Versions:        []protocol.Version{protocol.Version1_3},
		SelectedVersion: true,
	})
	cipherSuiteID := uint16(flightCtx.state.CipherSuite.ID())

	if flightCtx.state.SelectedGroup != 0 {
		exts = append(exts, &extension.KeyShare{
			SelectedGroup: &flightCtx.state.SelectedGroup,
		})
	}

	if len(flightCtx.state.Cookie) > 0 {
		exts = append(exts, &extension.CookieExt{
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
