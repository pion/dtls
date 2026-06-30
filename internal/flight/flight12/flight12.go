// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

type Flight uint8

const (
	Flight0 Flight = iota + 1
	Flight1
	Flight2
	Flight3
	Flight4
	Flight4b
	Flight5
	Flight5b
	Flight6
)

func (f Flight) String() string { //nolint:cyclop
	switch f {
	case Flight0:
		return "Flight 0"
	case Flight1:
		return "Flight 1"
	case Flight2:
		return "Flight 2"
	case Flight3:
		return "Flight 3"
	case Flight4:
		return "Flight 4"
	case Flight4b:
		return "Flight 4b"
	case Flight5:
		return "Flight 5"
	case Flight5b:
		return "Flight 5b"
	case Flight6:
		return "Flight 6"
	default:
		return "Invalid Flight"
	}
}

func (f Flight) IsLastSendFlight() bool {
	return f == Flight6 || f == Flight5b
}

func (f Flight) IsLastRecvFlight() bool {
	return f == Flight5 || f == Flight4b
}
