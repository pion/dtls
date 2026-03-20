// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"time"

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

type handshakeFSM13 struct {
	currentFlight flightVal13
	// 1.3 uses new record layer! We should replace with new packet struct.
	// flights            []*packet
	retransmit         bool //nolint:unused
	retransmitInterval time.Duration
	state              *State
	cache              *handshakeCache
	cfg                *handshakeConfig13
	closed             chan struct{}
}

type handshakeConfig13 struct {
	*handshakeConfig
	onFlightState13 func(flightVal13, handshakeState)
}

type flightConn13 interface { //nolint:unused
	notify(ctx context.Context, level alert.Level, desc alert.Description) error
	writePackets(context.Context, []*packet) error
	recvHandshake() <-chan recvHandshakeState
	handleQueuedPackets(context.Context) error
	sessionKey() []byte
}

func (s *handshakeFSM13) Run(ctx context.Context, conn flightConn, initialState handshakeState) error {
	state := initialState
	defer func() {
		close(s.closed)
	}()
	for {
		s.cfg.log.Tracef("[handshake13:%s] %s: %s", srvCliStr(s.state.isClient), s.currentFlight.String(), state.String())
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

func (s *handshakeFSM13) prepare(ctx context.Context, conn flightConn) (handshakeState, error) {
	return handshakeErrored, errStateUnimplemented13
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
