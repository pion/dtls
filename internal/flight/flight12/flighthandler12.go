// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package flight12 contains DTLS 1.2 flight handlers.
package flight12

import (
	"context"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

const keyLogLabelTLS12 = "CLIENT_RANDOM"

const (
	cookieLength  = 20
	sessionLength = 32
)

type flightParser12 func(
	context.Context,
	dtlsflight.Conn,
	*dtlsstate.State,
	*dtlsflight.Cache,
	*dtlsconfig.HandshakeConfig,
) (dtlsflight.Flight12, *alert.Alert, error)

type Generator func(
	dtlsflight.Conn,
	*dtlsstate.State,
	*dtlsflight.Cache,
	*dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Packet, *alert.Alert, error)

func getFlight12Parser(f dtlsflight.Flight12) (flightParser12, bool) { //nolint:cyclop
	switch f {
	case dtlsflight.Flight0:
		return flight0Parse, true
	case dtlsflight.Flight1:
		return flight1Parse, true
	case dtlsflight.Flight2:
		return flight2Parse, true
	case dtlsflight.Flight3:
		return flight3Parse, true
	case dtlsflight.Flight4:
		return flight4Parse, true
	case dtlsflight.Flight4b:
		return flight4bParse, true
	case dtlsflight.Flight5:
		return flight5Parse, true
	case dtlsflight.Flight5b:
		return flight5bParse, true
	case dtlsflight.Flight6:
		return flight6Parse, true
	default:
		return nil, false
	}
}

func GetGenerator(f dtlsflight.Flight12) (gen Generator, retransmit bool, ok bool) { //nolint:cyclop
	switch f {
	case dtlsflight.Flight0:
		return flight0Generate, true, true
	case dtlsflight.Flight1:
		return flight1Generate, true, true
	case dtlsflight.Flight2:
		// https://tools.ietf.org/html/rfc6347#section-3.2.1
		// HelloVerifyRequests must not be retransmitted.
		return flight2Generate, false, true
	case dtlsflight.Flight3:
		return flight3Generate, true, true
	case dtlsflight.Flight4:
		return flight4Generate, true, true
	case dtlsflight.Flight4b:
		return flight4bGenerate, true, true
	case dtlsflight.Flight5:
		return flight5Generate, true, true
	case dtlsflight.Flight5b:
		return flight5bGenerate, true, true
	case dtlsflight.Flight6:
		return flight6Generate, true, true
	default:
		return nil, false, false
	}
}

func Parse(
	ctx context.Context,
	f dtlsflight.Flight12,
	conn dtlsflight.Conn,
	state *dtlsstate.State,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (dtlsflight.Flight12, *alert.Alert, error, bool) {
	parse, ok := getFlight12Parser(f)
	if !ok {
		return 0, nil, nil, false
	}

	nextFlight, dtlsAlert, err := parse(ctx, conn, state, cache, cfg)

	return nextFlight, dtlsAlert, err, true
}
