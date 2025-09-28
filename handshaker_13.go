// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"fmt"
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

type handshakeState13 uint8

const (
	handshakeErrored13 handshakeState13 = iota
	handshakePreparing13
	handshakeSending13
	handshakeWaiting13
	handshakeFinished13
)

func (s handshakeState13) String() string {
	switch s {
	case handshakeErrored13:
		return "Errored"
	case handshakePreparing13:
		return "Preparing"
	case handshakeSending13:
		return "Sending"
	case handshakeWaiting13:
		return "Waiting"
	case handshakeFinished13:
		return "Finished"
	default:
		return "Unknown"
	}
}

type handshakeFSM13 struct {
	currentFlight      flightVal13
	flights            []*packet
	retransmit         bool
	retransmitInterval time.Duration
	state              *State
	cache              *handshakeCache
	cfg                *handshakeConfig13
	closed             chan struct{}
}

type handshakeConfig13 struct {
	handshakeConfig
	onFlightState13 func(flightVal13, handshakeState13)
}

type flightConn13 interface {
	notify(ctx context.Context, level alert.Level, desc alert.Description) error
	writePackets(context.Context, []*packet) error
	recvHandshake() <-chan recvHandshakeState
	setLocalEpoch(epoch uint16)
	handleQueuedPackets(context.Context) error
	sessionKey() []byte
}

func (c *handshakeConfig13) writeKeyLog(label string, clientRandom, secret []byte) {
	if c.keyLogWriter == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := fmt.Fprintf(c.keyLogWriter, "%s %x %x\n", label, clientRandom, secret)
	if err != nil {
		c.log.Debugf("failed to write key log file: %s", err)
	}
}

func newHandshakeFSM13(
	s *State, cache *handshakeCache, cfg *handshakeConfig13,
	initialFlight flightVal13,
) *handshakeFSM13 {
	return &handshakeFSM13{
		currentFlight:      initialFlight,
		state:              s,
		cache:              cache,
		cfg:                cfg,
		retransmitInterval: cfg.initialRetransmitInterval,
		closed:             make(chan struct{}),
	}
}

func (s *handshakeFSM13) Run(ctx context.Context, conn flightConn, initialState handshakeState13) error {
	state := initialState
	defer func() {
		close(s.closed)
	}()
	for {
		s.cfg.log.Tracef("[handshake:%s] %s: %s", srvCliStr(s.state.isClient), s.currentFlight.String(), state.String())
		if s.cfg.onFlightState != nil {
			s.cfg.onFlightState13(s.currentFlight, state)
		}
		var err error
		switch state {
		case handshakePreparing13:
			state, err = s.prepare(ctx, conn)
		case handshakeSending13:
			state, err = s.send(ctx, conn)
		case handshakeWaiting13:
			state, err = s.wait(ctx, conn)
		case handshakeFinished13:
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

func (s *handshakeFSM13) prepare(ctx context.Context, conn flightConn) (handshakeState13, error) {
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
		return handshakeErrored13, err
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
		s.cfg.log.Tracef("[handshake:%s] -> changeCipherSpec (epoch: %d)", srvCliStr(s.state.isClient), nextEpoch)
		conn.setLocalEpoch(nextEpoch)
	}

	return handshakeSending13, nil
}

func (s *handshakeFSM13) send(ctx context.Context, c flightConn) (handshakeState13, error) {
	// Send flights
	if err := c.writePackets(ctx, s.flights); err != nil {
		return handshakeErrored13, err
	}

	if s.currentFlight.isLastSendFlight() {
		return handshakeFinished13, nil
	}

	return handshakeWaiting13, nil
}

func (s *handshakeFSM13) wait(ctx context.Context, conn flightConn) (handshakeState13, error) { //nolint:gocognit,cyclop
	parse, errFlight := s.currentFlight.getFlightParser13()
	if errFlight != nil {
		if alertErr := conn.notify(ctx, alert.Fatal, alert.InternalError); alertErr != nil {
			return handshakeErrored13, alertErr
		}

		return handshakeErrored13, errFlight
	}

	retransmitTimer := time.NewTimer(s.retransmitInterval)
	for {
		select {
		case state := <-conn.recvHandshake():
			if state.isRetransmit {
				close(state.done)

				return handshakeSending13, nil
			}

			nextFlight, alert, err := parse(ctx, conn, s.state, s.cache, s.cfg)
			s.retransmitInterval = s.cfg.initialRetransmitInterval
			close(state.done)
			if alert != nil {
				if alertErr := conn.notify(ctx, alert.Level, alert.Description); alertErr != nil {
					if err != nil {
						err = alertErr
					}
				}
			}
			if err != nil {
				return handshakeErrored13, err
			}
			if nextFlight == 0 {
				break
			}
			s.cfg.log.Tracef(
				"[handshake:%s] %s -> %s",
				srvCliStr(s.state.isClient),
				s.currentFlight.String(),
				nextFlight.String(),
			)
			if nextFlight.isLastRecvFlight() && s.currentFlight == nextFlight {
				return handshakeFinished13, nil
			}
			s.currentFlight = nextFlight

			return handshakePreparing13, nil

		case <-retransmitTimer.C:
			if !s.retransmit {
				return handshakeWaiting13, nil
			}

			// RFC 4347 4.2.4.1:
			// Implementations SHOULD use an initial timer value of 1 second (the minimum defined in RFC 2988 [RFC2988])
			// and double the value at each retransmission, up to no less than the RFC 2988 maximum of 60 seconds.
			if !s.cfg.disableRetransmitBackoff {
				s.retransmitInterval *= 2
			}
			if s.retransmitInterval > time.Second*60 {
				s.retransmitInterval = time.Second * 60
			}

			return handshakeSending13, nil
		case <-ctx.Done():
			s.retransmitInterval = s.cfg.initialRetransmitInterval

			return handshakeErrored13, ctx.Err()
		}
	}
}

func (s *handshakeFSM13) finish(ctx context.Context, c flightConn) (handshakeState13, error) {
	select {
	case state := <-c.recvHandshake():
		close(state.done)
		if s.state.isClient {
			return handshakeFinished13, nil
		} else {
			return handshakeSending13, nil
		}
	case <-ctx.Done():
		return handshakeErrored13, ctx.Err()
	}
}
