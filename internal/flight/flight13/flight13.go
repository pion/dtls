// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

type Flight uint8

const (
	Flight0 Flight = iota + 1
	Flight1
	Flight2
	Flight3
	Flight4
	Flight5
)

func (f Flight) String() string { //nolint:cyclop
	switch f {
	case Flight0:
		return "Flight13 0"
	case Flight1:
		return "Flight13 1"
	case Flight2:
		return "Flight13 2"
	case Flight3:
		return "Flight13 3"
	case Flight4:
		return "Flight13 4"
	case Flight5:
		return "Flight13 5"
	default:
		return "Invalid Flight"
	}
}
