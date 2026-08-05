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
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
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
	flightACK          reliableFlight
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
		postHandshake: newPostHandshake(handshakeContext{
			state: state, cache: cache, cfg: cfg, transcript: initialTranscript,
		}),
	}
	fsm.prepareFlightACKTracking(fsm.flights, fsm.retransmit)
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
	s.prepareFlightACKTracking(s.flights, s.retransmit)
	if err := s.commitPreparedFlight(conn, s.currentFlight, s.flights); err != nil {
		return StateErrored, err
	}

	return StateSending, nil
}

func (s *fsm13) send(ctx context.Context, conn Conn) (State, error) {
	defer s.received.release()

	result, err := conn.WritePackets(ctx, s.flights)
	if err != nil {
		return StateErrored, err
	}
	s.flightACK.track(result)
	finished, err := s.afterSend(ctx, conn, s.currentFlight)
	if err != nil {
		return StateErrored, err
	}
	if finished && len(s.flightACK.pending) == 0 {
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
				s.received.release()

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

func (s *fsm13) finish(ctx context.Context, conn Conn) (State, error) {
	s.postHandshake.initialize()
	if err := s.postHandshake.startQueuedPostHandshake(ctx, conn); err != nil {
		return StateErrored, err
	}

	timer, timerC := s.postHandshake.nextTimer()
	if timer != nil {
		defer timer.Stop()
	}

	select {
	case received := <-conn.RecvHandshake():
		s.received.retain(received)
		defer s.received.release()
		if err := s.postHandshake.handlePostHandshakeReceive(ctx, conn, received); err != nil {
			return StateErrored, err
		}

	case command := <-s.postHandshake.commands:
		s.postHandshake.queue = append(s.postHandshake.queue, command)

	case now := <-timerC:
		if err := s.postHandshake.retransmitPostHandshake(ctx, conn, now, s.cfg.DisableRetransmitBackoff); err != nil {
			return StateErrored, err
		}

	case <-ctx.Done():
		return StateErrored, ctx.Err()
	}

	return StateFinished, nil
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
	ackResult := s.flightACK.acknowledge(received.ACKs)
	s.applyACKProgress(ackResult)
	if !received.HasHandshake && len(received.ACKs) != 0 {
		return s.transitionAfterACK(ackResult, false), nil
	}

	nextFlight, err := s.parseReceivedFlight(ctx, conn, s.currentFlight)
	if err != nil {
		return receivedFlightTransition{}, err
	}
	if nextFlight == 0 {
		if ackErr := sendACK(ctx, conn, s.state.LocalEpoch(), received.RecordsToACK); ackErr != nil {
			return receivedFlightTransition{}, ackErr
		}

		return s.transitionAfterACK(ackResult, received.IsRetransmit), nil
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

func (s *fsm13) prepareFlightACKTracking(flights []*dtlsflight.Packet, retransmit bool) {
	s.flightACK.reset()
	if retransmit {
		for _, packet := range flights {
			_, packet.ShouldTrackACK = packet.Record.Content.(*handshake.Handshake)
		}
	}
}

func (s *fsm13) applyACKProgress(result ACKResult) {
	for _, progress := range result.Messages {
		remaining := s.flights[:0]
		for _, packet := range s.flights {
			message, ok := packet.Record.Content.(*handshake.Handshake)
			if !ok || message.Header.MessageSequence != progress.MessageSequence {
				remaining = append(remaining, packet)
			} else if !progress.Complete {
				packet.HandshakeFragmentOffsets = s.flightACK.pendingForMessage(progress.MessageSequence)
				remaining = append(remaining, packet)
			}
		}
		s.flights = remaining
	}
}

func (s *fsm13) transitionAfterACK(result ACKResult, peerRetransmit bool) receivedFlightTransition {
	if len(result.Messages) != 0 && len(s.flightACK.pending) == 0 {
		s.retransmit = false
		if s.currentFlight.IsLastSendFlight() {
			return receivedFlightTransition{state: StateFinished}
		}

		return receivedFlightTransition{state: StateWaiting}
	}
	if result.Empty || len(result.Messages) != 0 || peerRetransmit {
		return receivedFlightTransition{
			state: handleRetransmitTimeout(s.retransmit, &s.retransmitInterval, s.cfg),
		}
	}

	return receivedFlightTransition{state: StateWaiting}
}
