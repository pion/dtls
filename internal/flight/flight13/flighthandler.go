// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package flight13 contains DTLS 1.3 flight handlers.
package flight13

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
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

// ParseHooks provides the DTLS 1.3 handshake operations invoked while parsing
// a flight.
type ParseHooks struct {
	InboundHandshake                     InboundHandshakeHandler
	ProtectedHandshake                   ProtectedHandshakeHandler
	HandshakeTrafficSecretDeriver        HandshakeTrafficSecretDeriver
	HandshakeRecordProtectionInitializer HandshakeRecordProtectionInitializer
}

// ParseDependencies provides the state and callbacks required to parse a DTLS
// 1.3 flight.
type ParseDependencies struct {
	State  *dtlsstate.State13
	Cache  *dtlsflight.Cache
	Config *dtlsconfig.HandshakeConfig
	Hooks  ParseHooks
}

type flightParseFailure struct {
	alert *alert.Alert
	err   error
}

type protectedFlightPull struct {
	nextHandshakeSequence int
	items                 []*dtlsflight.HandshakeCacheItem
	ready                 bool
	failure               *flightParseFailure
}

type handshakeContext struct {
	state                                *dtlsstate.State13
	cache                                *dtlsflight.Cache
	cfg                                  *dtlsconfig.HandshakeConfig
	inboundHandshakeHandler              InboundHandshakeHandler
	protectedHandshakeHandler            ProtectedHandshakeHandler
	handshakeTrafficSecretDeriver        HandshakeTrafficSecretDeriver
	handshakeRecordProtectionInitializer HandshakeRecordProtectionInitializer
}

func (h *handshakeContext) handleInboundHandshake(
	items []*dtlsflight.HandshakeCacheItem,
) *flightParseFailure {
	if h.inboundHandshakeHandler == nil {
		return nil
	}
	if err := h.inboundHandshakeHandler(h.state.CipherSuite, items); err != nil {
		return newFlightParseFailure(alert.InternalError, err)
	}

	return nil
}

func newFlightParseFailure(
	description alert.Description,
	err error,
) *flightParseFailure {
	dtlsAlert := &alert.Alert{Level: alert.Fatal, Description: description}
	if err != nil {
		err = fmt.Errorf("%w: %w", dtlsAlert, err)
	}

	return &flightParseFailure{
		alert: dtlsAlert,
		err:   err,
	}
}

func newHandshakeContext(dependencies ParseDependencies) *handshakeContext {
	return &handshakeContext{
		state:                                dependencies.State,
		cache:                                dependencies.Cache,
		cfg:                                  dependencies.Config,
		inboundHandshakeHandler:              dependencies.Hooks.InboundHandshake,
		protectedHandshakeHandler:            dependencies.Hooks.ProtectedHandshake,
		handshakeTrafficSecretDeriver:        dependencies.Hooks.HandshakeTrafficSecretDeriver,
		handshakeRecordProtectionInitializer: dependencies.Hooks.HandshakeRecordProtectionInitializer,
	}
}

func pullProtectedHandshakeFlight(
	cache *dtlsflight.Cache,
	rules []dtlsflight.HandshakeCachePullRule,
	nextHandshakeSequence int,
) protectedFlightPull {
	selection := cache.PullSequential(nextHandshakeSequence, rules...)
	if selection.Err != nil {
		return protectedFlightPull{
			ready:   true,
			failure: &flightParseFailure{err: selection.Err},
		}
	}
	if !selection.Ready {
		return protectedFlightPull{}
	}

	items := make([]*dtlsflight.HandshakeCacheItem, 0, len(selection.Items))
	sequence := nextHandshakeSequence
	for i, item := range selection.Items {
		if item == nil {
			continue
		}
		failure := validateProtectedHandshakeItem(
			item,
			rules[i].Typ,
			uint16(sequence), //nolint:gosec // PullSequential bounded sequence.
		)
		if failure != nil {
			return protectedFlightPull{ready: true, failure: failure}
		}
		sequence++
		items = append(items, item)
	}

	return protectedFlightPull{
		nextHandshakeSequence: selection.NextSequence,
		items:                 items,
		ready:                 true,
	}
}

func validateProtectedHandshakeItem(
	item *dtlsflight.HandshakeCacheItem,
	expectedType handshake.Type,
	expectedSequence uint16,
) *flightParseFailure {
	if item.MessageSequence != expectedSequence || item.Typ != expectedType {
		return newFlightParseFailure(alert.DecodeError, dtlserrors.ErrInvalidHandshakeTranscriptMessage)
	}

	header := &handshake.Header{}
	if err := header.Unmarshal(item.Data); err != nil {
		return newFlightParseFailure(alert.DecodeError, err)
	}
	if header.Type != expectedType || header.MessageSequence != expectedSequence ||
		header.FragmentOffset != 0 ||
		header.FragmentLength != header.Length ||
		len(item.Data) != handshake.HeaderLength+int(header.Length) {
		return newFlightParseFailure(alert.DecodeError, dtlserrors.ErrInvalidHandshakeTranscriptMessage)
	}

	if err := unmarshalProtectedHandshakeMessage(expectedType, item.Data[handshake.HeaderLength:]); err != nil {
		return &flightParseFailure{err: fmt.Errorf(
			"%w: %w",
			err,
			&alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
		)}
	}

	return nil
}

func unmarshalProtectedHandshakeMessage(typ handshake.Type, body []byte) error {
	var msg handshake.Message
	switch typ {
	case handshake.TypeEncryptedExtensions:
		msg = &handshake.MessageEncryptedExtensions{}
	case handshake.TypeCertificateRequest:
		msg = &handshake.MessageCertificateRequest13{}
	case handshake.TypeCertificate:
		msg = &handshake.MessageCertificate13{}
	case handshake.TypeCertificateVerify:
		msg = &handshake.MessageCertificateVerify{}
	case handshake.TypeFinished:
		msg = &handshake.MessageFinished{}
	default:
		return dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	return msg.Unmarshal(body)
}

func getFlightParser(f Flight) (flightParser, bool) {
	switch f {
	case Flight0:
		return flight0Parse, true
	case Flight1:
		return flight1Parse, true
	case Flight2:
		return flight2Parse, true
	case Flight3:
		return flight3Parse, true
	case Flight4:
		return flight4Parse, true
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
		return gen(conn, newHandshakeContext(ParseDependencies{
			State:  state,
			Cache:  cache,
			Config: cfg,
		}))
	}
}

func GetGenerator(f Flight) (gen Generator, retransmit bool, ok bool) {
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
	case Flight5:
		return adaptFlightGenerator(flight5Generate), true, true
	default:
		return nil, false, false
	}
}

func Parse(
	ctx context.Context,
	f Flight,
	conn dtlsflight.Conn,
	dependencies ParseDependencies,
) (Flight, *alert.Alert, error, bool) {
	parse, ok := getFlightParser(f)
	if !ok {
		return 0, nil, nil, false
	}

	nextFlight, dtlsAlert, err := parse(ctx, conn, newHandshakeContext(dependencies))
	if dtlsAlert == nil && err != nil {
		errors.As(err, &dtlsAlert)
	}

	return nextFlight, dtlsAlert, err, true
}

func HandshakePacket(message handshake.Message) *dtlsflight.Packet {
	return &dtlsflight.Packet{
		Record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
				Epoch:   EpochHandshake,
			},
			Content: &handshake.Handshake{Message: message},
		},
		ShouldEncrypt: true,
	}
}

func CertificateVerifyPacket(
	message *handshake.MessageCertificateVerify,
	signer crypto.Signer,
) *dtlsflight.Packet {
	pkt := HandshakePacket(message)
	pkt.CertificateVerifySigner = signer

	return pkt
}

type serverHelloPull struct {
	nextHandshakeSequence int
	serverHello           *handshake.MessageServerHello
	items                 []*dtlsflight.HandshakeCacheItem
	ready                 bool
	failure               *flightParseFailure
}

func IsHelloRetryRequest(sh *handshake.MessageServerHello) bool {
	randomBytes := sh.Random.MarshalFixed()

	return bytes.Equal(randomBytes[:], handshake.HelloRetryRequestRandom())
}

func ServerHelloSelectedVersions(extensions []extension.Value) ([]protocol.Version, bool, error) {
	seenSupportedVersions := false
	var versions []protocol.Version
	for _, val := range extensions {
		supportedVersions, ok := val.(*extension13.SelectedVersion)
		if !ok {
			continue
		}
		if seenSupportedVersions {
			return nil, true, dtlserrors.ErrInvalidServerHello
		}
		seenSupportedVersions = true
		versions = []protocol.Version{supportedVersions.Version}
	}

	return versions, seenSupportedVersions, nil
}

func validateHelloRetryRequestSelectedVersion(extensions []extension.Value) error {
	versions, seenSupportedVersions, err := ServerHelloSelectedVersions(extensions)
	if err != nil {
		return dtlserrors.ErrInvalidHelloRetryRequest
	}
	if !seenSupportedVersions {
		return dtlserrors.ErrMissingSupportedVersionsExtension
	}
	if !versions[0].Equal(protocol.Version1_3) {
		return dtlserrors.ErrUnsupportedProtocolVersion
	}

	return nil
}

func selectServerHelloCipherSuite(
	serverHello *handshake.MessageServerHello,
	cfg *dtlsconfig.HandshakeConfig,
) (dtlsconfig.CipherSuite, *alert.Alert, error) {
	if serverHello.CipherSuiteID == nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
			dtlserrors.ErrInvalidServerHello
	}
	remoteCipherSuite := ciphersuite.ForID(ciphersuite.ID(*serverHello.CipherSuiteID), cfg.CustomCipherSuites)
	if remoteCipherSuite == nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity},
			dtlserrors.ErrCipherSuiteNoIntersection
	}
	if !ciphersuite.IDSupportsVersion(remoteCipherSuite.ID(), protocol.Version1_3) {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity},
			dtlserrors.ErrInvalidCipherSuite
	}
	selectedCipherSuite, found := dtlsflight.FindMatchingCipherSuite(
		[]dtlsconfig.CipherSuite{remoteCipherSuite}, cfg.LocalCipherSuites,
	)
	if !found {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity},
			dtlserrors.ErrInvalidCipherSuite
	}

	return selectedCipherSuite, nil, nil
}

func serverHelloKeyShare(extensions []extension.Value) *extension13.KeyShareEntry {
	for _, ext := range extensions {
		keyShare, ok := ext.(*extension13.ServerKeyShare)
		if !ok {
			continue
		}

		return &keyShare.Share
	}

	return nil
}

func protectedFlightParseFailure(err error) *flightParseFailure {
	switch {
	case errors.Is(err, dtlserrors.ErrVerifyDataMismatch):
		return newFlightParseFailure(alert.HandshakeFailure, err)
	case errors.Is(err, dtlserrors.ErrCertificateVerifyNoCertificate):
		return newFlightParseFailure(alert.NoCertificate, err)
	case errors.Is(err, dtlserrors.ErrClientCertificateRequired):
		return newFlightParseFailure(alert.CertificateRequired, err)
	case errors.Is(err, dtlserrors.ErrKeySignatureMismatch),
		errors.Is(err, dtlserrors.ErrInvalidCertificate),
		errors.Is(err, dtlserrors.ErrCertificateVerificationFailed),
		errors.Is(err, dtlserrors.ErrClientCertificateNotVerified),
		errors.Is(err, dtlserrors.ErrInvalidCertificateOID),
		errors.Is(err, dtlserrors.ErrInvalidCertificateSignatureAlgorithm),
		errors.Is(err, dtlserrors.ErrNotAcceptableCertificateChain):
		return newFlightParseFailure(alert.BadCertificate, err)
	case errors.Is(err, dtlserrors.ErrNoAvailableSignatureSchemes):
		return newFlightParseFailure(alert.InsufficientSecurity, err)
	default:
		return newFlightParseFailure(alert.InternalError, err)
	}
}
