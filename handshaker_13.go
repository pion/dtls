// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"time"

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

type handshakeFSM13 struct {
	currentFlight      flightVal13
	flights            []*packet //nolint:unused
	retransmit         bool      //nolint:unused
	retransmitInterval time.Duration
	state              *State
	cache              *handshakeCache
	cfg                *handshakeConfig
	transcript         *handshakeTranscript13
	closed             chan struct{}
}

func newHandshakeFSM13(
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
	initialFlight flightVal13,
	initialFlights []*packet,
	initialTranscript *handshakeTranscript13,
) (*handshakeFSM13, error) {
	if initialTranscript == nil {
		initialTranscript = newHandshakeTranscript13()
	}

	fsm := &handshakeFSM13{
		currentFlight:      initialFlight,
		flights:            initialFlights,
		retransmit:         initialFlights != nil,
		state:              state,
		cache:              cache,
		cfg:                cfg,
		transcript:         initialTranscript,
		retransmitInterval: cfg.initialRetransmitInterval,
		closed:             make(chan struct{}),
	}
	if err := fsm.seedTranscriptFromInitialFlights(); err != nil {
		return nil, err
	}

	return fsm, nil
}

func (s *handshakeFSM13) flightContext() *handshakeContext13 {
	return &handshakeContext13{
		state:      s.state,
		cache:      s.cache,
		cfg:        s.cfg,
		transcript: s.transcript,
	}
}

// seedTranscriptFromInitialFlights handles the dual-stack ClientHello generated
// before the DTLS 1.3 FSM exists.
func (s *handshakeFSM13) seedTranscriptFromInitialFlights() error {
	if !s.state.isClient {
		return nil
	}

	appended, err := appendClientHelloInitialFlights13(s.transcript, s.flights)
	if err != nil {
		return err
	}
	if s.retransmit && !appended {
		return errHandshakeTranscriptMissingClientHello
	}

	return nil
}

func appendClientHelloInitialFlights13(transcript *handshakeTranscript13, flights []*packet) (bool, error) {
	if transcript == nil {
		return false, errHandshakeTranscriptMissingClientHello
	}

	appended := false
	for _, p := range flights {
		seq, canonical, ok, err := canonicalClientHelloInitialFlight13(p)
		if err != nil {
			return false, err
		}
		if !ok {
			continue
		}
		if err := transcript.appendCanonical(transcriptMessageID13{
			sender: transcriptClient13,
			seq:    seq,
		}, canonical); err != nil {
			return false, err
		}
		appended = true
	}

	return appended, nil
}

func canonicalClientHelloInitialFlight13(p *packet) (uint16, []byte, bool, error) {
	if p == nil || p.record == nil {
		return 0, nil, false, nil
	}
	hand, ok := p.record.Content.(*handshake.Handshake)
	if !ok {
		return 0, nil, false, nil
	}
	if hand.Message == nil || hand.Message.Type() != handshake.TypeClientHello {
		return 0, nil, false, nil
	}

	raw, err := hand.Marshal()
	if err != nil {
		return 0, nil, false, err
	}
	canonical, err := canonicalHandshake13(raw)
	if err != nil {
		return 0, nil, false, err
	}

	return hand.Header.MessageSequence, canonical, true, nil
}

//nolint:dupl
func (s *handshakeFSM13) Run(ctx context.Context, conn flightConn, initialState handshakeState) error {
	state := initialState
	defer func() {
		close(s.closed)
	}()
	for {
		s.cfg.log.Tracef("[handshake13:%s] %s: %s", srvCliStr(s.state.isClient), s.currentFlight.String(), state.String())
		// nolint:godox
		// TODO:: refactor callback, see discussion in https://github.com/pion/dtls/pull/738#discussion_r3131501159
		if s.cfg.onFlightState13 != nil {
			s.cfg.onFlightState13(s.currentFlight, state)
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
			return errInvalidFSMTransition
		}
		if err != nil {
			return err
		}
	}
}

func (s *handshakeFSM13) Done() <-chan struct{} {
	return s.closed
}

//nolint:dupl
func (s *handshakeFSM13) prepare(ctx context.Context, conn flightConn) (handshakeState, error) {
	s.flights = nil
	// Prepare flights
	var (
		dtlsAlert *alert.Alert
		err       error
		pkts      []*packet
	)
	gen, retransmit, errFlight := s.currentFlight.getFlightGenerator13()
	if errFlight != nil {
		err = errFlight
		dtlsAlert = &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}
	} else {
		pkts, dtlsAlert, err = gen(conn, s.state, s.cache, s.cfg)
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
	epoch := s.cfg.initialEpoch
	nextEpoch := epoch
	for _, p := range s.flights {
		p.record.Header.Epoch += epoch
		if p.record.Header.Epoch > nextEpoch {
			nextEpoch = p.record.Header.Epoch
		}
		if h, ok := p.record.Content.(*handshake.Handshake); ok {
			h.Header.MessageSequence = uint16(s.state.handshakeSendSequence) //nolint:gosec // G115
			s.state.handshakeSendSequence++
		}
	}
	if epoch != nextEpoch {
		s.cfg.log.Tracef("[handshake13:%s] -> changeCipherSpec (epoch: %d)", srvCliStr(s.state.isClient), nextEpoch)
		conn.setLocalEpoch(nextEpoch)
	}

	return handshakeSending, nil
}

func (s *handshakeFSM13) send(ctx context.Context, c flightConn) (handshakeState, error) {
	return handshakeErrored, errStateUnimplemented13
}

func (s *handshakeFSM13) wait(ctx context.Context, conn flightConn) (handshakeState, error) {
	return handshakeErrored, errStateUnimplemented13
}

func (s *handshakeFSM13) finish(ctx context.Context, c flightConn) (handshakeState, error) {
	return handshakeErrored, errStateUnimplemented13
}
