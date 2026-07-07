// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"
	"time"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight12 "github.com/pion/dtls/v3/internal/flight/flight12"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
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
	currentFlight      dtlsflight12.Flight
	flights            []*dtlsflight.Packet
	retransmit         bool
	retransmitInterval time.Duration
	state              *dtlsstate.State12
	cache              *dtlsflight.Cache
	cfg                *dtlsconfig.HandshakeConfig
	closed             chan struct{}
}

func NewFSM12(
	state *dtlsstate.State12,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	initialFlight dtlsflight12.Flight,
	initialFlights []*dtlsflight.Packet,
) FSM {
	return newFSM12(state, cache, cfg, initialFlight, initialFlights)
}

func newFSM12(
	state *dtlsstate.State12,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	initialFlight dtlsflight12.Flight,
	initialFlights []*dtlsflight.Packet,
) *fsm12 {
	return &fsm12{
		currentFlight:      initialFlight,
		flights:            initialFlights,
		retransmit:         initialFlights != nil,
		state:              state,
		cache:              cache,
		cfg:                cfg,
		retransmitInterval: cfg.InitialRetransmitInterval,
		closed:             make(chan struct{}),
	}
}

//nolint:dupl
func (s *fsm12) Run(ctx context.Context, conn Conn, initialState State) error {
	state := initialState
	defer func() {
		close(s.closed)
	}()
	for {
		s.cfg.Log.Tracef("[handshake:%s] %s: %s", sideString(s.state.IsClient), s.currentFlight.String(), state.String())
		if s.cfg.OnFlightState != nil {
			s.cfg.OnFlightState(uint8(s.currentFlight), uint8(state))
		}
		var err error
		switch state {
		case StatePreparing:
			state, err = s.prepare(ctx, conn)
		case StateSending:
			state, err = s.send(ctx, conn)
		case StateWaiting:
			state, err = s.wait(ctx, conn)
		case StateFinished:
			state, err = s.finish(ctx, conn)
		default:
			return dtlserrors.ErrInvalidFSMTransition
		}
		if err != nil {
			return err
		}
	}
}

func (s *fsm12) Done() <-chan struct{} {
	return s.closed
}

//nolint:dupl
func (s *fsm12) prepare(ctx context.Context, conn Conn) (State, error) {
	s.flights = nil
	// Prepare flights
	var (
		dtlsAlert *alert.Alert
		err       error
		pkts      []*dtlsflight.Packet
	)
	gen, retransmit, ok := dtlsflight12.GetGenerator(s.currentFlight)
	if !ok {
		err = dtlserrors.ErrInvalidFlight
		dtlsAlert = &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}
	} else {
		pkts, dtlsAlert, err = gen(conn, s.state, s.cache, s.cfg)
		s.retransmit = retransmit
	}
	if dtlsAlert != nil {
		if alertErr := conn.Notify(ctx, dtlsAlert.Level, dtlsAlert.Description); alertErr != nil {
			if err != nil {
				err = alertErr
			}
		}
	}
	if err != nil {
		return StateErrored, err
	}

	s.flights = pkts
	epoch := s.cfg.InitialEpoch
	nextEpoch := epoch
	for _, p := range s.flights {
		p.Record.Header.Epoch += epoch
		if p.Record.Header.Epoch > nextEpoch {
			nextEpoch = p.Record.Header.Epoch
		}
		if h, ok := p.Record.Content.(*handshake.Handshake); ok {
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
	if err := c.WritePackets(ctx, s.flights); err != nil {
		return StateErrored, err
	}

	if s.currentFlight.IsLastSendFlight() {
		return StateFinished, nil
	}

	return StateWaiting, nil
}

func (s *fsm12) wait(ctx context.Context, conn Conn) (State, error) { //nolint:gocognit,cyclop
	retransmitTimer := time.NewTimer(s.retransmitInterval)
	for {
		select {
		case state := <-conn.RecvHandshake():
			if !state.IsRetransmit {
				// only reset retransmit interval on non-retransmit state
				// https://github.com/pion/dtls/issues/758
				s.retransmitInterval = s.cfg.InitialRetransmitInterval
			}

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
					return StateErrored, alertErr
				}

				return StateErrored, dtlserrors.ErrInvalidFlight
			}
			close(state.Done)
			if dtlsAlert != nil {
				if alertErr := conn.Notify(ctx, dtlsAlert.Level, dtlsAlert.Description); alertErr != nil {
					if err != nil {
						err = alertErr
					}
				}
			}
			if err != nil {
				return StateErrored, err
			}
			if nextFlight == 0 {
				break
			}
			s.cfg.Log.Tracef(
				"[handshake:%s] %s -> %s",
				sideString(s.state.IsClient),
				s.currentFlight.String(),
				nextFlight.String(),
			)
			if nextFlight.IsLastRecvFlight() && s.currentFlight == nextFlight {
				return StateFinished, nil
			}
			s.currentFlight = nextFlight

			return StatePreparing, nil

		case <-retransmitTimer.C:
			if !s.retransmit {
				return StateWaiting, nil
			}

			// RFC 4347 4.2.4.1:
			// Implementations SHOULD use an initial timer value of 1 second (the minimum defined in RFC 2988 [RFC2988])
			// and double the value at each retransmission, up to no less than the RFC 2988 maximum of 60 seconds.
			if !s.cfg.DisableRetransmitBackoff {
				s.retransmitInterval *= 2
			}
			if s.retransmitInterval > time.Second*60 {
				s.retransmitInterval = time.Second * 60
			}

			return StateSending, nil
		case <-ctx.Done():
			s.retransmitInterval = s.cfg.InitialRetransmitInterval

			return StateErrored, ctx.Err()
		}
	}
}

func (s *fsm12) finish(ctx context.Context, c Conn) (State, error) {
	select {
	case state := <-c.RecvHandshake():
		close(state.Done)
		if s.state.IsClient {
			return StateFinished, nil
		}

		return StateSending, nil
	case <-ctx.Done():
		return StateErrored, ctx.Err()
	}
}
