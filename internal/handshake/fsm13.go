// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"
	"time"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

// [RFC9147 Section-5.8.1]
//                            +-----------+
//                            | PREPARING |
//               +----------> |           |
//               |            |           |
//               |            +-----------+
//               |                  |
//               |                  | Buffer next flight
//               |                  |
//               |                 \|/
//               |            +-----------+
//               |            |           |
//               |            |  SENDING  |<------------------+
//               |            |           |                   |
//               |            +-----------+                   |
//       Receive |                  |                         |
//          next |                  | Send flight or partial  |
//        flight |                  | flight                  |
//               |                  |                         |
//               |                  | Set retransmit timer    |
//               |                 \|/                        |
//               |            +-----------+                   |
//               |            |           |                   |
//               +------------|  WAITING  |-------------------+
//               |     +----->|           |   Timer expires   |
//               |     |      +-----------+                   |
//               |     |          |  |   |                    |
//               |     |          |  |   |                    |
//               |     +----------+  |   +--------------------+
//               |    Receive record |   Read retransmit or ACK
//       Receive |  (Maybe Send ACK) |
//          last |                   |
//        flight |                   | Receive ACK
//               |                   | for last flight
//              \|/                  |
//                                   |
//           +-----------+           |
//           |           | <---------+
//           | FINISHED  |
//           |           |
//           +-----------+
//               |  /|\
//               |   |
//               |   |
//               +---+
//
//         Server read retransmit
//             Retransmit ACK

type fsm13 struct {
	currentFlight      dtlsflight13.Flight
	flights            []*dtlsflight.Packet
	retransmit         bool
	retransmitInterval time.Duration
	handshakeContext
	closed        chan struct{}
	establishment *Establishment
	postHandshake *postHandshake
	received      recvHandshakeLease // keeps the reader paused across a prepare/send transition
}

func NewFSM13(
	state *dtlsstate.State13,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	initialFlight dtlsflight13.Flight,
	initialFlights []*dtlsflight.Packet,
	establishment *Establishment,
) (FSM, error) {
	return newFSM13WithEstablishment(state, cache, cfg, initialFlight, initialFlights, nil, establishment)
}

func newFSM13(
	state *dtlsstate.State13,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	initialFlight dtlsflight13.Flight,
	initialFlights []*dtlsflight.Packet,
	initialTranscript *Transcript,
) (*fsm13, error) {
	return newFSM13WithEstablishment(
		state, cache, cfg, initialFlight, initialFlights, initialTranscript, NewEstablishment(),
	)
}

func newFSM13WithEstablishment(
	state *dtlsstate.State13,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	initialFlight dtlsflight13.Flight,
	initialFlights []*dtlsflight.Packet,
	initialTranscript *Transcript,
	establishment *Establishment,
) (*fsm13, error) {
	if initialTranscript == nil {
		initialTranscript = NewTranscript()
	}

	fsm := &fsm13{
		currentFlight:      initialFlight,
		flights:            initialFlights,
		retransmit:         initialFlights != nil,
		handshakeContext:   handshakeContext{state: state, cache: cache, cfg: cfg, transcript: initialTranscript},
		retransmitInterval: cfg.InitialRetransmitInterval,
		closed:             make(chan struct{}),
		establishment:      establishment,
		postHandshake:      newPostHandshake(cfg.InitialRetransmitInterval),
	}
	if err := fsm.seedInitialFlights(fsm.flights, fsm.retransmit); err != nil {
		return nil, err
	}

	return fsm, nil
}

func (s *fsm13) Run(ctx context.Context, conn Conn, initialState State) error {
	defer s.received.release()

	return runHandshakeFSM(
		ctx,
		conn,
		initialState,
		s.closed,
		s.establishment,
		func(state State) {
			s.cfg.Log.Tracef(
				"[handshake13:%s] %s: %s",
				sideString(s.state.IsClient),
				s.currentFlight.String(),
				state.String(),
			)
		},
		s.prepare,
		s.send,
		s.wait,
		s.finish,
	)
}

func (s *fsm13) Done() <-chan struct{} {
	return s.closed
}

func (s *fsm13) prepare(ctx context.Context, conn Conn) (nextState State, err error) {
	defer func() {
		if err != nil {
			s.received.release()
		}
	}()

	s.flights = nil
	// Prepare flights
	var (
		dtlsAlert *alert.Alert
		pkts      []*dtlsflight.Packet
	)
	gen, retransmit, ok := dtlsflight13.GetGenerator(s.currentFlight)
	if !ok {
		err = dtlserrors.ErrFlightUnimplemented13
		dtlsAlert = &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}
	} else {
		pkts, dtlsAlert, err = gen(conn, s.state, s.cache, s.cfg)
		s.retransmit = retransmit
	}
	if err = notifyAlert(ctx, conn, dtlsAlert, err); err != nil {
		return StateErrored, err
	}

	s.flights = pkts
	if err := s.commitPreparedFlight(conn, s.currentFlight, s.flights); err != nil {
		return StateErrored, err
	}

	return StateSending, nil
}

func (s *fsm13) send(ctx context.Context, conn Conn) (State, error) {
	defer s.received.release()

	if _, err := conn.WritePackets(ctx, s.flights); err != nil {
		return StateErrored, err
	}
	finished, err := s.afterSend(ctx, conn, s.currentFlight)
	if err != nil {
		return StateErrored, err
	}
	if finished {
		return StateFinished, nil
	}

	return StateWaiting, nil
}

func (s *fsm13) wait(ctx context.Context, conn Conn) (State, error) {
	retainPendingRecv := false
	defer func() {
		if !retainPendingRecv {
			s.received.release()
		}
	}()

	retransmitTimer := time.NewTimer(s.retransmitInterval)
	defer retransmitTimer.Stop()
	for {
		select {
		case received := <-conn.RecvHandshake():
			transition, err := s.handleReceivedFlight(ctx, conn, received)
			if err != nil {
				return StateErrored, err
			}
			if transition.state == StateWaiting {
				continue
			}
			retainPendingRecv = transition.retainPendingRecv

			return transition.state, nil

		case <-retransmitTimer.C:
			return handleRetransmitTimeout(s.retransmit, &s.retransmitInterval, s.cfg), nil
		case <-ctx.Done():
			return handleWaitCancellation(&s.retransmitInterval, s.cfg, ctx.Err())
		}
	}
}

func (s *fsm13) finish(ctx context.Context, c Conn) (State, error) {
	s.postHandshake.initialize(s.state.IsClient)

	select {
	case state := <-c.RecvHandshake():
		close(state.Done)

		// avoid committing a second time.
		return StateFinished, nil
	case <-ctx.Done():
		return StateErrored, ctx.Err()
	}
}

func (s *fsm13) handleReceivedFlight(
	ctx context.Context,
	conn Conn,
	received RecvHandshakeState,
) (receivedFlightTransition, error) {
	// Keep the reader paused while this receive state is parsed.
	s.received.retain(received)
	if !received.IsRetransmit {
		s.retransmitInterval = s.cfg.InitialRetransmitInterval
	}

	nextFlight, err := s.parseReceivedFlight(ctx, conn, s.currentFlight)
	if err != nil {
		return receivedFlightTransition{}, err
	}
	if nextFlight == 0 {
		s.received.release()

		return receivedFlightTransition{state: StateWaiting}, nil
	}

	transition, err := s.advanceAfterReceivedFlight(ctx, conn, s.currentFlight, nextFlight, received.RecordsToACK)
	if err != nil {
		return receivedFlightTransition{}, err
	}
	if transition.nextFlight != 0 {
		s.currentFlight = transition.nextFlight
	}

	return transition, nil
}
