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

const (
	EpochInitial     uint16 = 0
	EpochEarlyData   uint16 = 1
	EpochHandshake   uint16 = 2
	EpochApplication uint16 = 3
)

type flightParser func(
	context.Context,
	dtlsflight.Conn,
	*handshakeContext,
) (Flight, *alert.Alert, error)

type contextFlightGenerator func(dtlsflight.Conn, *handshakeContext) ([]*dtlsflight.Packet, *alert.Alert, error)

type Generator func(
	dtlsflight.Conn,
	*dtlsstate.State13,
	*dtlsflight.Cache,
	*dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Packet, *alert.Alert, error)

type InboundHandshakeHandler func(dtlsconfig.CipherSuite, []*dtlsflight.HandshakeCacheItem) error

type ProtectedHandshakeHandler func(dtlsconfig.CipherSuite, []*dtlsflight.HandshakeCacheItem) error

type HandshakeTrafficSecretDeriver func(*dtlsstate.State13) error

type HandshakeRecordProtectionInitializer func(*dtlsstate.State13) error

type handshakeContext struct {
	state                                *dtlsstate.State13
	cache                                *dtlsflight.Cache
	cfg                                  *dtlsconfig.HandshakeConfig
	inboundHandshakeHandler              InboundHandshakeHandler
	protectedHandshakeHandler            ProtectedHandshakeHandler
	handshakeTrafficSecretDeriver        HandshakeTrafficSecretDeriver
	handshakeRecordProtectionInitializer HandshakeRecordProtectionInitializer
}

func getFlightParser(f Flight) (flightParser, bool) { //nolint:cyclop
	switch f {
	case Flight0:
		return flight0Parse, true
	case Flight1:
		return flight1Parse, true
	case Flight2:
		return flight2Parse, true
	case Flight3:
		return flight3Parse, true
	default:
		return nil, false
	}
}

func adaptFlightGenerator(gen contextFlightGenerator) Generator {
	return func(
		conn dtlsflight.Conn,
		state *dtlsstate.State13,
		cache *dtlsflight.Cache,
		cfg *dtlsconfig.HandshakeConfig,
	) ([]*dtlsflight.Packet, *alert.Alert, error) {
		return gen(conn, &handshakeContext{state: state, cache: cache, cfg: cfg})
	}
}

func GetGenerator(f Flight) (gen Generator, retransmit bool, ok bool) { //nolint:cyclop
	switch f {
	case Flight0:
		return adaptFlightGenerator(flight0Generate), true, true
	case Flight1:
		return adaptFlightGenerator(flight1Generate), true, true
	case Flight2:
		// HelloRetryRequests must not be retransmitted.
		return adaptFlightGenerator(flight2Generate), false, true
	case Flight3:
		return adaptFlightGenerator(flight3Generate), true, true
	case Flight4:
		return adaptFlightGenerator(flight4Generate), true, true
	default:
		return nil, false, false
	}
}

func Parse(
	ctx context.Context,
	f Flight,
	conn dtlsflight.Conn,
	state *dtlsstate.State13,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	inboundHandshakeHandler InboundHandshakeHandler,
	protectedHandshakeHandler ProtectedHandshakeHandler,
	handshakeTrafficSecretDeriver HandshakeTrafficSecretDeriver,
	handshakeRecordProtectionInitializer HandshakeRecordProtectionInitializer,
) (Flight, *alert.Alert, error, bool) {
	parse, ok := getFlightParser(f)
	if !ok {
		return 0, nil, nil, false
	}

	nextFlight, dtlsAlert, err := parse(ctx, conn, &handshakeContext{
		state:                                state,
		cache:                                cache,
		cfg:                                  cfg,
		inboundHandshakeHandler:              inboundHandshakeHandler,
		protectedHandshakeHandler:            protectedHandshakeHandler,
		handshakeTrafficSecretDeriver:        handshakeTrafficSecretDeriver,
		handshakeRecordProtectionInitializer: handshakeRecordProtectionInitializer,
	})

	return nextFlight, dtlsAlert, err, true
}
