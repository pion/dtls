// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/stretchr/testify/require"
)

const renegotiationInfoSCSV uint16 = 0x00ff

type handshakeContext13 struct {
	state      *dtlsstate.State
	cache      *dtlsflight.Cache
	cfg        *handshakeConfig
	transcript *handshakeTranscript13
}

func (s *handshakeFSM13) flightContext() *handshakeContext13 {
	return &handshakeContext13{
		state:      s.state,
		cache:      s.cache,
		cfg:        s.cfg,
		transcript: s.transcript,
	}
}

func flight13ParseForTest(
	testingT require.TestingT,
	flight dtlsflight.Flight13,
	ctx context.Context,
	flightCtx *handshakeContext13,
) (dtlsflight.Flight13, *alert.Alert, error) {
	if helper, ok := testingT.(interface{ Helper() }); ok {
		helper.Helper()
	}

	nextFlight, dtlsAlert, err, ok := dtlsflight13.Parse(
		ctx,
		flight,
		nil,
		flightCtx.state,
		flightCtx.cache,
		flightCtx.cfg,
		func(cipherSuite dtlsconfig.CipherSuite, items []*dtlsflight.HandshakeCacheItem) error {
			return appendInboundHandshakeCacheItems13(flightCtx.transcript, cipherSuite, items)
		},
		func(state *dtlsstate.State) error {
			return deriveAndStoreHandshakeTrafficSecrets13(state, flightCtx.transcript)
		},
	)
	require.True(testingT, ok)

	return nextFlight, dtlsAlert, err
}

func flight13GenerateForTest(
	testingT require.TestingT,
	flight dtlsflight.Flight13,
	flightCtx *handshakeContext13,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	if helper, ok := testingT.(interface{ Helper() }); ok {
		helper.Helper()
	}

	gen, _, ok := dtlsflight13.GetGenerator(flight)
	require.True(testingT, ok)

	return gen(nil, flightCtx.state, flightCtx.cache, flightCtx.cfg)
}
