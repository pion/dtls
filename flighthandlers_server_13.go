// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/rand"

	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

// we'll add the flight handlers for the DTLS 1.3 server here.
//
// Flight0
//
// +----------+
// | Flight 2 |
// | Flight 4 |
// | Flight 6 |
// +----------+
//
// +-----------+
// | Flight 4a |
// | Flight 6a |
// +-----------+
//
// +-----------+
// | Flight 4b |
// | Flight 6b |
// +-----------+
//
// +-----------+
// | Flight 4c |
// +-----------+

func flight13_0Generate(
	_ flightConn,
	state *State,
	_ *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *alert.Alert, error) { //nolint:unparam
	// Initialize
	if !cfg.insecureSkipHelloVerify {
		state.cookie = make([]byte, cookieLength)
		if _, err := rand.Read(state.cookie); err != nil {
			return nil, nil, err
		}
	}

	var zeroEpoch uint16
	state.localEpoch.Store(zeroEpoch)
	state.remoteEpoch.Store(zeroEpoch)
	if len(cfg.ellipticCurves) < 1 {
		return nil, nil, errEmptyEllipticCurves
	}
	state.namedCurve = cfg.ellipticCurves[0]

	if err := state.localRandom.Populate(); err != nil {
		return nil, nil, err
	}

	return nil, nil, nil
}
