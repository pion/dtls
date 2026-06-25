// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

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

type handshakeState uint8

const (
	handshakeErrored handshakeState = iota
	handshakePreparing
	handshakeSending
	handshakeWaiting
	handshakeFinished
)

func (s handshakeState) String() string {
	switch s {
	case handshakeErrored:
		return "Errored"
	case handshakePreparing:
		return "Preparing"
	case handshakeSending:
		return "Sending"
	case handshakeWaiting:
		return "Waiting"
	case handshakeFinished:
		return "Finished"
	default:
		return "Unknown"
	}
}

type handshakeFSM12 struct {
	currentFlight      dtlsflight.Flight12
	flights            []*dtlsflight.Packet
	retransmit         bool
	retransmitInterval time.Duration
	state              *dtlsstate.State
	cache              *dtlsflight.Cache
	cfg                *handshakeConfig
	closed             chan struct{}
}

type handshakeConfig = dtlsconfig.HandshakeConfig

type flightConn interface {
	notify(ctx context.Context, level alert.Level, desc alert.Description) error
	writePackets(context.Context, []*dtlsflight.Packet) error
	recvHandshake() <-chan recvHandshakeState
	setLocalEpoch(epoch uint16)
	handleQueuedPackets(context.Context) error
	sessionKey() []byte
}

type flightConnAdapter struct {
	flightConn
}

func (c flightConnAdapter) HandleQueuedPackets(ctx context.Context) error {
	return c.handleQueuedPackets(ctx)
}

func (c flightConnAdapter) SessionKey() []byte {
	return c.sessionKey()
}

func adaptFlightConn(conn flightConn) dtlsflight.Conn {
	if conn == nil {
		return nil
	}

	return flightConnAdapter{conn}
}

func srvCliStr(isClient bool) string {
	if isClient {
		return "client"
	}

	return "server"
}

func newHandshakeFSM12(
	s *dtlsstate.State, cache *dtlsflight.Cache, cfg *handshakeConfig,
	initialFlight dtlsflight.Flight12,
) *handshakeFSM12 {
	return &handshakeFSM12{
		currentFlight:      initialFlight,
		state:              s,
		cache:              cache,
		cfg:                cfg,
		retransmitInterval: cfg.InitialRetransmitInterval,
		closed:             make(chan struct{}),
	}
}

type handshakeFSM interface {
	Done() <-chan struct{}
	Run(ctx context.Context, conn flightConn, initialState handshakeState) error
	finish(ctx context.Context, c flightConn) (handshakeState, error)
	prepare(ctx context.Context, conn flightConn) (handshakeState, error)
	send(ctx context.Context, c flightConn) (handshakeState, error)
	wait(ctx context.Context, conn flightConn) (handshakeState, error)
}

//nolint:dupl
func (s *handshakeFSM12) Run(ctx context.Context, conn flightConn, initialState handshakeState) error {
	state := initialState
	defer func() {
		close(s.closed)
	}()
	for {
		s.cfg.Log.Tracef("[handshake:%s] %s: %s", srvCliStr(s.state.IsClient), s.currentFlight.String(), state.String())
		if s.cfg.OnFlightState != nil {
			s.cfg.OnFlightState(uint8(s.currentFlight), uint8(state))
		}
		var err error
		switch state {
		case handshakePreparing:
			state, err = s.prepare(ctx, conn)
		case handshakeSending:
			state, err = s.send(ctx, conn)
		case handshakeWaiting:
			state, err = s.wait(ctx, conn)
		case handshakeFinished:
			state, err = s.finish(ctx, conn)
		default:
			return dtlserrors.ErrInvalidFSMTransition
		}
		if err != nil {
			return err
		}
	}
}

func (s *handshakeFSM12) Done() <-chan struct{} {
	return s.closed
}

//nolint:dupl
func (s *handshakeFSM12) prepare(ctx context.Context, conn flightConn) (handshakeState, error) {
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
		pkts, dtlsAlert, err = gen(adaptFlightConn(conn), s.state, s.cache, s.cfg)
		s.retransmit = retransmit
	}
	if dtlsAlert != nil {
		if alertErr := conn.notify(ctx, dtlsAlert.Level, dtlsAlert.Description); alertErr != nil {
			if err != nil {
				err = alertErr
			}
		}
	}
	if err != nil {
		return handshakeErrored, err
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
		s.cfg.Log.Tracef("[handshake:%s] -> changeCipherSpec (epoch: %d)", srvCliStr(s.state.IsClient), nextEpoch)
		conn.setLocalEpoch(nextEpoch)
	}

	return handshakeSending, nil
}

func (s *handshakeFSM12) send(ctx context.Context, c flightConn) (handshakeState, error) {
	// Send flights
	if err := c.writePackets(ctx, s.flights); err != nil {
		return handshakeErrored, err
	}

	if s.currentFlight.IsLastSendFlight() {
		return handshakeFinished, nil
	}

	return handshakeWaiting, nil
}

func (s *handshakeFSM12) wait(ctx context.Context, conn flightConn) (handshakeState, error) { //nolint:gocognit,cyclop
	retransmitTimer := time.NewTimer(s.retransmitInterval)
	for {
		select {
		case state := <-conn.recvHandshake():
			if !state.isRetransmit {
				// only reset retransmit interval on non-retransmit state
				// https://github.com/pion/dtls/issues/758
				s.retransmitInterval = s.cfg.InitialRetransmitInterval
			}

			nextFlight, dtlsAlert, err, ok := dtlsflight12.Parse(
				ctx,
				s.currentFlight,
				adaptFlightConn(conn),
				s.state,
				s.cache,
				s.cfg,
			)
			if !ok {
				if alertErr := conn.notify(ctx, alert.Fatal, alert.InternalError); alertErr != nil {
					return handshakeErrored, alertErr
				}

				return handshakeErrored, dtlserrors.ErrInvalidFlight
			}
			close(state.done)
			if dtlsAlert != nil {
				if alertErr := conn.notify(ctx, dtlsAlert.Level, dtlsAlert.Description); alertErr != nil {
					if err != nil {
						err = alertErr
					}
				}
			}
			if err != nil {
				return handshakeErrored, err
			}
			if nextFlight == 0 {
				break
			}
			s.cfg.Log.Tracef(
				"[handshake:%s] %s -> %s",
				srvCliStr(s.state.IsClient),
				s.currentFlight.String(),
				nextFlight.String(),
			)
			if nextFlight.IsLastRecvFlight() && s.currentFlight == nextFlight {
				return handshakeFinished, nil
			}
			s.currentFlight = nextFlight

			return handshakePreparing, nil

		case <-retransmitTimer.C:
			if !s.retransmit {
				return handshakeWaiting, nil
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

			return handshakeSending, nil
		case <-ctx.Done():
			s.retransmitInterval = s.cfg.InitialRetransmitInterval

			return handshakeErrored, ctx.Err()
		}
	}
}

func (s *handshakeFSM12) finish(ctx context.Context, c flightConn) (handshakeState, error) {
	select {
	case state := <-c.recvHandshake():
		close(state.done)
		if s.state.IsClient {
			return handshakeFinished, nil
		} else {
			return handshakeSending, nil
		}
	case <-ctx.Done():
		return handshakeErrored, ctx.Err()
	}
}
