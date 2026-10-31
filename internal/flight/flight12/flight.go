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

func (f Flight) String() string {
	names := [...]string{
		Flight0:  "Flight 0",
		Flight1:  "Flight 1",
		Flight2:  "Flight 2",
		Flight3:  "Flight 3",
		Flight4:  "Flight 4",
		Flight4b: "Flight 4b",
		Flight5:  "Flight 5",
		Flight5b: "Flight 5b",
		Flight6:  "Flight 6",
	}
	if int(f) < len(names) && names[f] != "" {
		return names[f]
	}

	return "Invalid Flight"
}

func (f Flight) IsLastSendFlight() bool {
	return f == Flight6 || f == Flight5b
}

func (f Flight) IsLastRecvFlight() bool {
	return f == Flight5 || f == Flight4b
}
