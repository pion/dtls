// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"context"
	"crypto/rand"
	"slices"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/internal/negotiation"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

//nolint:cyclop,gocognit,gocyclo
func flight0Parse(
	_ context.Context,
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) (Flight, *alert.Alert, error) {
	state := flightCtx.state
	cache := flightCtx.cache
	cfg := flightCtx.cfg

	if state.LocalVersion != protocol.Version1_3 {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, dtlserrors.ErrInvalidProtocolVersionState
	}
	pull := cache.FullPullMapItems(0, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},
	)
	if pull.Err != nil {
		return 0, nil, pull.Err
	}
	if !pull.Ready {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	// Connection Identifiers must be negotiated afresh on session resumption.
	// https://datatracker.ietf.org/doc/html/rfc9146#name-the-connection_id-extension
	state.ResetConnectionIDs()
	state.RemoteClientHelloSnapshots.Reset()
	state.HelloRetryRequest = negotiation.RetryRequest{}

	state.HandshakeRecvSequence = pull.NextSequence

	// Validate type
	clientHello, ok := pull.Messages[handshake.TypeClientHello].(*handshake.MessageClientHello)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if clientHello.Version != protocol.Version1_2 {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlserrors.ErrUnsupportedProtocolVersion
	}
	state.RemoteRandom = clientHello.Random

	cipherSuites := []dtlsconfig.CipherSuite{}
	for _, id := range clientHello.CipherSuiteIDs {
		if id == renegotiationInfoSCSV {
			continue
		}
		if c, found := dtlsflight.FindCipherSuiteByID(id, cfg.LocalCipherSuites); found && c.Capabilities().SupportsVersion(protocol.Version1_3) {
			cipherSuites = append(cipherSuites, c)
		}
	}
	if state.CipherSuite, ok = dtlsflight.FindMatchingCipherSuite(cipherSuites, cfg.LocalCipherSuites); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrCipherSuiteNoIntersection
	}

	if failure := processClientHelloExtensions(state, clientHello); failure != nil {
		return 0, failure.alert, failure.err
	}

	if !slices.Contains(state.RemoteVersions, protocol.Version1_3) {
		// nolint:godox
		// TODO: This should actually handover the state machine to DTLS 1.2
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, dtlserrors.ErrInvalidProtocolVersionState
	}

	nextFlight := Flight2

	selectClientKeyShare(state, cfg)

	if cfg.InsecureSkipHelloVerify {
		if _, ok := matchingClientKeyShare(state, cfg); ok {
			if failure := generateClientKeyShareSecret(state, cfg); failure != nil {
				return 0, failure.alert, failure.err
			}
			nextFlight = Flight4
		}
	}

	if flightCtx.inboundHandshakeHandler != nil {
		if err := flightCtx.inboundHandshakeHandler(state.CipherSuite, pull.Items); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}
	if err := state.RemoteClientHelloSnapshots.RecordWire(pull.Items[0].Raw.Data); err != nil {
		return 0, nil, err
	}

	return nextFlight, nil, nil
}

// nolint:unparam
func flight0Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	state := flightCtx.state
	cfg := flightCtx.cfg
	state.SetSRTPProtectionProfile(0)

	if !cfg.InsecureSkipHelloVerify {
		state.Cookie = make([]byte, cookieLength)
		if _, err := rand.Read(state.Cookie); err != nil {
			return nil, nil, err
		}
	}

	state.SetLocalEpoch(EpochInitial)
	state.SetRemoteEpoch(EpochInitial)
	if len(cfg.EllipticCurves) == 0 {
		return nil, nil, dtlserrors.ErrEmptyEllipticCurves
	}

	if err := state.LocalRandom.Populate(); err != nil {
		return nil, nil, err
	}

	return nil, nil, nil
}
