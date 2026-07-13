// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

// State is a DTLS handshake FSM state.
type State uint8

const (
	// StateErrored indicates the FSM has errored.
	StateErrored State = iota
	// StatePreparing indicates the FSM is preparing the next flight.
	StatePreparing
	// StateSending indicates the FSM is sending the prepared flight.
	StateSending
	// StateWaiting indicates the FSM is waiting for the peer's next flight.
	StateWaiting
	// StateFinished indicates the FSM has completed.
	StateFinished
)

func (s State) String() string {
	switch s {
	case StateErrored:
		return "Errored"
	case StatePreparing:
		return "Preparing"
	case StateSending:
		return "Sending"
	case StateWaiting:
		return "Waiting"
	case StateFinished:
		return "Finished"
	default:
		return "Unknown"
	}
}
