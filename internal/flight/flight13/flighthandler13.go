// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package flight13 contains DTLS 1.3 flight handlers.
package flight13

import (
	"context"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

const (
	cookieLength          = 20
	renegotiationInfoSCSV = 0x00ff
)

type flightParser13 func(
	context.Context,
	dtlsflight.Conn,
	*handshakeContext13,
) (Flight, *alert.Alert, error)

type contextFlightGenerator func(dtlsflight.Conn, *handshakeContext13) ([]*dtlsflight.Packet, *alert.Alert, error)

type Generator func(
	dtlsflight.Conn,
	*dtlsstate.State,
	*dtlsflight.Cache,
	*dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Packet, *alert.Alert, error)

type InboundHandshakeHandler func(dtlsconfig.CipherSuite, []*dtlsflight.HandshakeCacheItem) error

type HandshakeTrafficSecretDeriver func(*dtlsstate.State) error

type handshakeContext13 struct {
	state                         *dtlsstate.State
	cache                         *dtlsflight.Cache
	cfg                           *dtlsconfig.HandshakeConfig
	inboundHandshakeHandler       InboundHandshakeHandler
	handshakeTrafficSecretDeriver HandshakeTrafficSecretDeriver
}

func getFlight13Parser(f Flight) (flightParser13, bool) { //nolint:cyclop
	switch f {
	case Flight0:
		return flight13_0Parse, true
	case Flight1:
		return flight13_1Parse, true
	case Flight2:
		return flight13_2Parse, true
	case Flight3:
		return flight13_3Parse, true
	default:
		return nil, false
	}
}

func adaptFlight13Generator(gen contextFlightGenerator) Generator {
	return func(
		conn dtlsflight.Conn,
		state *dtlsstate.State,
		cache *dtlsflight.Cache,
		cfg *dtlsconfig.HandshakeConfig,
	) ([]*dtlsflight.Packet, *alert.Alert, error) {
		return gen(conn, &handshakeContext13{state: state, cache: cache, cfg: cfg})
	}
}

func GetGenerator(f Flight) (gen Generator, retransmit bool, ok bool) { //nolint:cyclop
	switch f {
	case Flight0:
		return adaptFlight13Generator(flight13_0Generate), true, true
	case Flight1:
		return adaptFlight13Generator(flight13_1Generate), true, true
	case Flight2:
		// HelloRetryRequests must not be retransmitted.
		return adaptFlight13Generator(flight13_2Generate), false, true
	case Flight3:
		return adaptFlight13Generator(flight13_3Generate), true, true
	case Flight4:
		return adaptFlight13Generator(flight13_4Generate), true, true
	default:
		return nil, false, false
	}
}

func Parse(
	ctx context.Context,
	f Flight,
	conn dtlsflight.Conn,
	state *dtlsstate.State,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	inboundHandshakeHandler InboundHandshakeHandler,
	handshakeTrafficSecretDeriver HandshakeTrafficSecretDeriver,
) (Flight, *alert.Alert, error, bool) {
	parse, ok := getFlight13Parser(f)
	if !ok {
		return 0, nil, nil, false
	}

	nextFlight, dtlsAlert, err := parse(ctx, conn, &handshakeContext13{
		state:                         state,
		cache:                         cache,
		cfg:                           cfg,
		inboundHandshakeHandler:       inboundHandshakeHandler,
		handshakeTrafficSecretDeriver: handshakeTrafficSecretDeriver,
	})

	return nextFlight, dtlsAlert, err, true
}
