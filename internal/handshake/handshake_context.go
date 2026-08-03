// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

// handshakeContext groups the DTLS 1.3 state that must move together while
// flights are generated, committed, and parsed.
type handshakeContext struct {
	state      *dtlsstate.State13
	cache      *dtlsflight.Cache
	cfg        *dtlsconfig.HandshakeConfig
	transcript *Transcript
}

func (c *handshakeContext) seedInitialFlights(flights []*dtlsflight.Packet, retransmit bool) error {
	return seedTranscriptFromInitialFlights(c.state, c.transcript, flights, retransmit)
}

func (c *handshakeContext) commitPreparedFlight(
	conn Conn,
	flight dtlsflight13.Flight,
	flights []*dtlsflight.Packet,
) error {
	if err := commitPreparedFlights(conn, c.state, c.transcript, c.cfg, flights); err != nil {
		return err
	}
	if !c.state.IsClient && flight == dtlsflight13.Flight4 {
		return DeriveAndStoreApplicationTrafficSecrets(c.state, c.transcript)
	}

	return nil
}

func (c *handshakeContext) afterSend(
	ctx context.Context,
	conn Conn,
	flight dtlsflight13.Flight,
) (bool, error) {
	if !c.state.IsClient &&
		flight == dtlsflight13.Flight4 &&
		c.state.GetRemoteEpoch() < dtlsflight13.EpochHandshake {
		// Only the first send advances the epoch and drains packets. A timer
		// retransmission has no receive-side rendezvous and the reader is active.
		c.state.RemoteEpoch.Store(dtlsflight13.EpochHandshake)
		if err := conn.HandleQueuedPackets(ctx); err != nil {
			return false, err
		}
	}
	if !c.state.IsClient || !flight.IsLastSendFlight() {
		return false, nil
	}

	return true, activateApplicationRecordProtection(ctx, conn, c.state)
}

func (c *handshakeContext) parseReceivedFlight(
	ctx context.Context,
	conn Conn,
	currentFlight dtlsflight13.Flight,
) (dtlsflight13.Flight, error) {
	nextFlight, dtlsAlert, err, ok := dtlsflight13.Parse(ctx, currentFlight, conn, c.parseDependencies())
	if !ok {
		if alertErr := conn.Notify(ctx, alert.Fatal, alert.InternalError); alertErr != nil {
			return 0, alertErr
		}

		return 0, dtlserrors.ErrFlightUnimplemented13
	}
	if err = notifyAlert(ctx, conn, dtlsAlert, err); err != nil {
		return 0, err
	}

	return nextFlight, nil
}

type receivedFlightTransition struct {
	state             State
	nextFlight        dtlsflight13.Flight
	retainPendingRecv bool
}

func (c *handshakeContext) advanceAfterReceivedFlight(
	ctx context.Context,
	conn Conn,
	currentFlight, nextFlight dtlsflight13.Flight,
	receivedRecords []protocol.RecordNumber,
) (receivedFlightTransition, error) {
	if c.state.IsClient && nextFlight.IsLastSendFlight() {
		if err := DeriveAndStoreApplicationTrafficSecrets(c.state, c.transcript); err != nil {
			return receivedFlightTransition{}, err
		}
	}
	if !c.state.IsClient &&
		currentFlight == nextFlight &&
		nextFlight.IsLastRecvFlight() {
		if err := activateApplicationRecordProtection(ctx, conn, c.state); err != nil {
			return receivedFlightTransition{}, err
		}
		if err := sendACK(ctx, conn, c.state.GetLocalEpoch(), receivedRecords); err != nil {
			return receivedFlightTransition{}, err
		}

		return receivedFlightTransition{state: StateFinished}, nil
	}

	c.cfg.Log.Tracef(
		"[handshake13:%s] %s -> %s",
		sideString(c.state.IsClient),
		currentFlight.String(),
		nextFlight.String(),
	)

	return receivedFlightTransition{
		state:             StatePreparing,
		nextFlight:        nextFlight,
		retainPendingRecv: c.transitionRequiresReaderPause(nextFlight),
	}, nil
}

func (c *handshakeContext) transitionRequiresReaderPause(nextFlight dtlsflight13.Flight) bool {
	if c.state.IsClient {
		return nextFlight.IsLastSendFlight()
	}

	return nextFlight == dtlsflight13.Flight4 &&
		c.state.GetRemoteEpoch() < dtlsflight13.EpochHandshake
}

func (c *handshakeContext) parseDependencies() dtlsflight13.ParseDependencies {
	return dtlsflight13.ParseDependencies{
		State:  c.state,
		Cache:  c.cache,
		Config: c.cfg,
		Hooks: dtlsflight13.ParseHooks{
			InboundHandshake: func(cipherSuite dtlsconfig.CipherSuite, items []*dtlsflight.HandshakeCacheItem) error {
				return AppendVerifiedInboundHandshakeCacheItems(c.transcript, cipherSuite, items)
			},
			ProtectedHandshake: func(cipherSuite dtlsconfig.CipherSuite, items []*dtlsflight.HandshakeCacheItem) error {
				return VerifyAndAppendProtectedHandshakeCacheItems13(
					c.transcript,
					c.state,
					c.cfg,
					cipherSuite,
					items,
				)
			},
			HandshakeTrafficSecretDeriver: func(state *dtlsstate.State13) error {
				return DeriveAndStoreHandshakeTrafficSecrets(state, c.transcript)
			},
			HandshakeRecordProtectionInitializer: InitHandshakeRecordProtection,
		},
	}
}
