// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"
	"time"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	dtlsflight12 "github.com/pion/dtls/v4/internal/flight/flight12"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

// [RFC6347 Section-4.2.4]
//                      +-----------+
//                +---> | PREPARING | <--------------------+
//                |     +-----------+                      |
//                |           |                            |
//                |           | Buffer next flight         |
//                |           |                            |
//                |          \|/                           |
//                |     +-----------+                      |
//                |     |  SENDING  |<------------------+  | Send
//                |     +-----------+                   |  | HelloRequest
//        Receive |           |                         |  |
//           next |           | Send flight             |  | or
//         flight |  +--------+                         |  |
//                |  |        | Set retransmit timer    |  | Receive
//                |  |       \|/                        |  | HelloRequest
//                |  |  +-----------+                   |  | Send
//                +--)--|  WAITING  |-------------------+  | ClientHello
//                |  |  +-----------+   Timer expires   |  |
//                |  |         |                        |  |
//                |  |         +------------------------+  |
//        Receive |  | Send           Read retransmit      |
//           last |  | last                                |
//         flight |  | flight                              |
//                |  |                                     |
//               \|/\|/                                    |
//            +-----------+                                |
//            | FINISHED  | -------------------------------+
//            +-----------+
//                 |  /|\
//                 |   |
//                 +---+
//              Read retransmit
//           Retransmit last flight

type fsm12 struct {
	currentFlight          dtlsflight12.Flight
	flights                []*dtlsflight.Outbound
	retransmit             bool
	retransmitInterval     time.Duration
	peerRetransmitAfter    time.Time
	peerRetransmitInterval time.Duration
	state                  *dtlsstate.State12
	cache                  *dtlsflight.Cache
	cfg                    *dtlsconfig.HandshakeConfig
	closed                 chan struct{}
	establishment          *Establishment
	received               recvHandshakeLease
}

func NewFSM12(state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig, initialFlight dtlsflight12.Flight, initialFlights []*dtlsflight.Outbound, establishment *Establishment) FSM {
	return &fsm12{currentFlight: initialFlight, flights: initialFlights, retransmit: initialFlights != nil, state: state, cache: cache, cfg: cfg, retransmitInterval: cfg.InitialRetransmitInterval, closed: make(chan struct{}), establishment: establishment}
}

func (s *fsm12) Run(ctx context.Context, conn Conn, initialState State) error {
	defer s.received.release()

	return runHandshakeFSM(
		ctx,
		conn,
		initialState,
		s.closed,
		s.establishment,
		func(state State) {
			if state == StateFinished {
				s.cache.Finish12()
				s.state.HandshakeComplete.Store(true)
			}
			s.cfg.Log.Tracef(
				"[handshake:%s] %s: %s",
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

func (s *fsm12) Done() <-chan struct{} {
	return s.closed
}

func (s *fsm12) prepare(ctx context.Context, conn Conn) (State, error) {
	s.flights = nil
	// Prepare flights
	var (
		dtlsAlert *alert.Alert
		err       error
		pkts      []*dtlsflight.Outbound
	)
	gen, retransmit, ok := dtlsflight12.GetGenerator(s.currentFlight)
	if !ok {
		err = dtlserrors.ErrInvalidFlight
		dtlsAlert = &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}
	} else {
		pkts, dtlsAlert, err = gen(conn, s.state, s.cache, s.cfg)
		s.retransmit = retransmit
	}
	if err = notifyAlert(ctx, conn, dtlsAlert, err); err != nil {
		return StateErrored, err
	}

	s.peerRetransmitAfter = time.Time{}
	s.peerRetransmitInterval = 0
	s.flights = pkts
	epoch := s.cfg.InitialEpoch
	nextEpoch := epoch
	for _, p := range s.flights {
		p.Epoch += epoch
		if p.Epoch > nextEpoch {
			nextEpoch = p.Epoch
		}
		if h, ok := p.Content.(*handshake.Handshake); ok {
			h.Header.MessageSequence = uint16(s.state.HandshakeSendSequence) //nolint:gosec // G115
			s.state.HandshakeSendSequence++
		}
	}
	if epoch != nextEpoch {
		s.cfg.Log.Tracef("[handshake:%s] -> changeCipherSpec (epoch: %d)", sideString(s.state.IsClient), nextEpoch)
		conn.SetLocalEpoch(nextEpoch)
	}

	return StateSending, nil
}

func (s *fsm12) send(ctx context.Context, c Conn) (State, error) {
	// Send flights
	if _, err := c.WritePackets(ctx, s.flights); err != nil {
		return StateErrored, err
	}

	if s.currentFlight.IsLastSendFlight() {
		return StateFinished, nil
	}

	return StateWaiting, nil
}

func (s *fsm12) wait(ctx context.Context, conn Conn) (State, error) {
	s.received.release()
	retransmitTimer := s.cfg.NewTimer(s.retransmitInterval)
	defer retransmitTimer.Stop()
	for {
		select {
		case state := <-conn.RecvHandshake():
			nextState, err := s.handleWaitingFlight(ctx, conn, state, retransmitTimer)
			if nextState != StateWaiting || err != nil {
				return nextState, err
			}

		case <-retransmitTimer.C():
			if s.retransmit {
				s.backoffPeerRetransmit()
			}

			return handleRetransmitTimeout(s.retransmit, &s.retransmitInterval, s.cfg), nil
		case <-ctx.Done():
			return handleWaitCancellation(&s.retransmitInterval, s.cfg, ctx.Err())
		}
	}
}

func (s *fsm12) parseWaitingFlight(ctx context.Context, conn Conn) (dtlsflight12.Flight, error) {
	nextFlight, dtlsAlert, err, ok := dtlsflight12.Parse(
		ctx,
		s.currentFlight,
		conn,
		s.state,
		s.cache,
		s.cfg,
	)
	if !ok {
		if alertErr := conn.Notify(ctx, alert.Fatal, alert.InternalError); alertErr != nil {
			return 0, alertErr
		}

		return 0, dtlserrors.ErrInvalidFlight
	}
	if dtlsAlert != nil {
		if alertErr := conn.Notify(ctx, dtlsAlert.Level, dtlsAlert.Description); alertErr != nil {
			if err != nil {
				err = alertErr
			}
		}
	}
	if err != nil {
		return 0, err
	}

	return nextFlight, nil
}

func (s *fsm12) handleIncompleteFlight(state RecvHandshakeState) (State, error) {
	if state.IsClientHelloRetransmit && s.currentFlight == dtlsflight12.Flight2 {
		return StateSending, nil
	}
	if state.IsClientHelloRetransmit &&
		(s.currentFlight == dtlsflight12.Flight4 || s.currentFlight == dtlsflight12.Flight4b) &&
		!time.Now().Before(s.peerRetransmitAfter) {
		s.backoffPeerRetransmit()

		return StateSending, nil
	}

	s.received.release()

	return StateWaiting, nil
}

func (s *fsm12) handleWaitingFlight(ctx context.Context, conn Conn, state RecvHandshakeState, retransmitTimer dtlsconfig.Timer) (State, error) {
	s.received.retain(state)
	nextFlight, err := s.parseWaitingFlight(ctx, conn)
	if err != nil {
		return StateErrored, err
	}
	if nextFlight == 0 {
		return s.handleIncompleteFlight(state)
	}
	if s.currentFlight == dtlsflight12.Flight3 && nextFlight == dtlsflight12.Flight3 {
		// A new cookie must not bypass or reset the retry backoff.
		select {
		case <-retransmitTimer.C():
			handleRetransmitTimeout(true, &s.retransmitInterval, s.cfg)
		case <-ctx.Done():
			return handleWaitCancellation(&s.retransmitInterval, s.cfg, ctx.Err())
		}
	} else if !state.IsRetransmit {
		s.retransmitInterval = s.cfg.InitialRetransmitInterval
	}
	s.cfg.Log.Tracef("[handshake:%s] %s -> %s", sideString(s.state.IsClient), s.currentFlight.String(), nextFlight.String())
	if nextFlight.IsLastRecvFlight() && s.currentFlight == nextFlight {
		return StateFinished, nil
	}
	s.currentFlight = nextFlight

	return StatePreparing, nil
}

// Rate-limit peer recovery separately from the configured retransmission timer.
func (s *fsm12) backoffPeerRetransmit() {
	backoffPeerRetransmit(&s.peerRetransmitAfter, &s.peerRetransmitInterval, s.cfg)
}

func (s *fsm12) finish(ctx context.Context, c Conn) (State, error) {
	s.received.release()
	select {
	case state := <-c.RecvHandshake():
		s.received.retain(state)
		if s.state.IsClient {
			return StateFinished, nil
		}

		return StateSending, nil
	case <-ctx.Done():
		return StateErrored, ctx.Err()
	}
}
