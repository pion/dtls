// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

type flightVal13 uint8

// TODO: Add all flights for DTLS 1.3
const (
	flight0_13 flightVal13 = iota + 1
	flight1_13
	flight2_13
)

func (f flightVal13) String() string { //nolint:cyclop
	switch f {
	case flight0_13:
		return "Flight 0"
	case flight1_13:
		return "Flight 1"
	case flight2_13:
		return "Flight 2"
	default:
		return "Invalid Flight"
	}
}

// TODO
func (f flightVal13) isLastSendFlight() bool {
	return f == flight2_13
}

// TODO
func (f flightVal13) isLastRecvFlight() bool {
	return f == flight1_13
}
