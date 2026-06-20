// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"

	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

type handshakeContext13 struct {
	state      *State
	cache      *handshakeCache
	cfg        *handshakeConfig
	transcript *handshakeTranscript13
}

// Parse received handshakes and return next flightVal.
type flightParser13 func( //nolint:unused
	context.Context,
	flightConn,
	*handshakeContext13,
) (flightVal13, *alert.Alert, error)

//nolint:unused
type flightGenerator13 func(flightConn, *handshakeContext13) ([]*packet, *alert.Alert, error)

//nolint:unused
func (f flightVal13) getFlightParser13() (flightParser13, error) {
	return nil, errFlightUnimplemented13
}

//nolint:unused
func (f flightVal13) getFlightGenerator13() (gen flightGenerator13, retransmit bool, err error) {
	switch f {
	case flight13_1:
		return flight13_1Generate, true, nil
	default:
		return nil, false, errFlightUnimplemented13
	}
}
