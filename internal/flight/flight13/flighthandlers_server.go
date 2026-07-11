// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"context"
	"crypto/rand"
	"slices"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// we'll add the flight handlers for the DTLS 1.3 server here.
//
// +----------+
// | Flight0  |
// +----------+
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

type clientHelloExtensionSet struct {
	hasPreSharedKey        bool
	hasSignatureAlgorithms bool
	hasSupportedGroups     bool
}

type clientHelloExtensionFailure struct {
	alert *alert.Alert
	err   error
}

func newClientHelloExtensionFailure(
	description alert.Description,
	err error,
) *clientHelloExtensionFailure {
	return &clientHelloExtensionFailure{
		alert: &alert.Alert{Level: alert.Fatal, Description: description},
		err:   err,
	}
}

func processClientHelloExtensions(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
	clientHello *handshake.MessageClientHello,
) *clientHelloExtensionFailure {
	var seen clientHelloExtensionSet

	for _, val := range clientHello.Extensions {
		if failure := processClientHelloSecurityExtension(state, cfg, &seen, val); failure != nil {
			return failure
		}
		processClientHelloStateExtension(state, cfg, val)
	}

	if !seen.hasPreSharedKey && (!seen.hasSignatureAlgorithms || !seen.hasSupportedGroups) {
		return newClientHelloExtensionFailure(alert.MissingExtension, dtlserrors.ErrMissingClientHelloExtension)
	}

	return nil
}

func processClientHelloSecurityExtension(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
	seen *clientHelloExtensionSet,
	val extension.Extension,
) *clientHelloExtensionFailure {
	switch ext := val.(type) {
	case *extension.SupportedEllipticCurves:
		seen.hasSupportedGroups = true
		if len(ext.EllipticCurves) == 0 {
			return newClientHelloExtensionFailure(alert.InsufficientSecurity, dtlserrors.ErrNoSupportedEllipticCurves)
		}
		state.RemoteGroups = ext.EllipticCurves
	case *extension.UseSRTP:
		profile, ok := dtlsflight.FindMatchingSRTPProfile(cfg.LocalSRTPProtectionProfiles, ext.ProtectionProfiles)
		if !ok {
			return newClientHelloExtensionFailure(alert.InsufficientSecurity, dtlserrors.ErrServerNoMatchingSRTPProfile)
		}
		state.SetSRTPProtectionProfile(profile)
		state.RemoteSRTPMasterKeyIdentifier = ext.MasterKeyIdentifier
	case *extension.SupportedSignatureAlgorithms:
		seen.hasSignatureAlgorithms = true
		state.RemoteSignatureSchemes = ext.SignatureHashAlgorithms
	case *extension.SupportedVersions:
		if ext.IsSelectedVersion() {
			return newClientHelloExtensionFailure(alert.IllegalParameter, dtlserrors.ErrInvalidClientHello)
		}
		state.RemoteVersions = ext.Versions
	case *extension.PreSharedKey:
		seen.hasPreSharedKey = true
	}

	return nil
}

func processClientHelloStateExtension(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
	val extension.Extension,
) {
	switch ext := val.(type) {
	case *extension.ServerName:
		state.ServerName = ext.ServerName // remote server name
	case *extension.ALPN:
		state.PeerSupportedProtocols = ext.ProtocolNameList
	case *extension.ConnectionID:
		// Only set connection ID to be sent if server supports connection IDs.
		if cfg.ConnectionIDGenerator != nil {
			state.RemoteConnectionID = ext.CID
		}
	case *extension.SignatureAlgorithmsCert:
		// Store the client's certificate signature schemes for later validation.
		state.RemoteCertSignatureSchemes = ext.SignatureHashAlgorithms
	case *extension.KeyShare:
		state.RemoteKeyEntries = &ext.ClientShares
	}
}

//nolint:cyclop,gocognit,gocyclo
func flight0Parse(
	_ context.Context,
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) (Flight, *alert.Alert, error) {
	state := flightCtx.state
	cache := flightCtx.cache
	cfg := flightCtx.cfg

	if state.LocalVersion != protocol.Version1_3 {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError},
			dtlserrors.ErrInvalidProtocolVersionState
	}
	seq, msgs, items, ok := cache.FullPullMapItems(0, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false}, //nolint:lll
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	// Connection Identifiers must be negotiated afresh on session resumption.
	// https://datatracker.ietf.org/doc/html/rfc9146#name-the-connection_id-extension
	state.SetLocalConnectionID(nil)
	state.RemoteConnectionID = nil

	state.HandshakeRecvSequence = seq

	var clientHello *handshake.MessageClientHello

	// Validate type
	if clientHello, ok = msgs[handshake.TypeClientHello].(*handshake.MessageClientHello); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if !clientHello.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
			dtlserrors.ErrUnsupportedProtocolVersion
	}

	state.RemoteRandom = clientHello.Random

	cipherSuites := []dtlsconfig.CipherSuite{}
	for _, id := range clientHello.CipherSuiteIDs {
		if id == renegotiationInfoSCSV {
			continue
		}
		if c := ciphersuite.ForID(ciphersuite.ID(id), cfg.CustomCipherSuites); c != nil {
			cipherSuites = append(cipherSuites, c)
		}
	}

	// nolint:godox
	// TODO: check for DTLS 1.3 cipher suites
	if state.CipherSuite, ok = dtlsflight.FindMatchingCipherSuite(cipherSuites, cfg.LocalCipherSuites); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrCipherSuiteNoIntersection //nolint:lll
	}

	if failure := processClientHelloExtensions(state, cfg, clientHello); failure != nil {
		return 0, failure.alert, failure.err
	}

	if !slices.Contains(state.RemoteVersions, protocol.Version1_3) {
		// nolint:godox
		// TODO: This should actually handover the state machine to DTLS 1.2
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError},
			dtlserrors.ErrInvalidProtocolVersionState
	}

	// If the client doesn't support connection IDs, the server should not
	// expect one to be sent.
	if state.RemoteConnectionID == nil {
		state.SetLocalConnectionID(nil)
	}

	nextFlight := Flight2

	selectClientKeyShare(state, cfg)

	if cfg.InsecureSkipHelloVerify {
		if _, ok := matchingClientKeyShare(state, cfg); ok {
			if failure := generateClientKeyShareSecret(state, cfg); failure != nil {
				return 0, failure.alert, failure.err
			}
			nextFlight = Flight4
		}
	}

	if flightCtx.inboundHandshakeHandler != nil {
		if err := flightCtx.inboundHandshakeHandler(state.CipherSuite, items); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	return nextFlight, nil, nil
}

// nolint:unparam
func flight0Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	state := flightCtx.state
	cfg := flightCtx.cfg

	if !cfg.InsecureSkipHelloVerify {
		state.Cookie = make([]byte, cookieLength)
		if _, err := rand.Read(state.Cookie); err != nil {
			return nil, nil, err
		}
	}

	state.LocalEpoch.Store(EpochInitial)
	state.RemoteEpoch.Store(EpochInitial)
	if len(cfg.EllipticCurves) < 1 {
		return nil, nil, dtlserrors.ErrEmptyEllipticCurves
	}

	if err := state.LocalRandom.Populate(); err != nil {
		return nil, nil, err
	}

	return nil, nil, nil
}

func flight2Parse(
	_ context.Context,
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) (Flight, *alert.Alert, error) {
	seq, msgs, items, ok := flightCtx.cache.FullPullMapItems(
		flightCtx.state.HandshakeRecvSequence, flightCtx.state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: flightCtx.cfg.InitialEpoch, IsClient: true, Optional: false}, //nolint:lll
	)
	if !ok {
		return 0, nil, nil
	}

	clientHello, ok := msgs[handshake.TypeClientHello].(*handshake.MessageClientHello)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if !clientHello.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
			dtlserrors.ErrUnsupportedProtocolVersion
	}

	cookie := clientHelloCookie(clientHello.Extensions)

	if len(cookie) == 0 {
		return 0, nil, nil
	}
	if !bytes.Equal(flightCtx.state.Cookie, cookie) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.AccessDenied}, dtlserrors.ErrCookieMismatch
	}

	if failure := processClientHelloExtensions(flightCtx.state, flightCtx.cfg, clientHello); failure != nil {
		return 0, failure.alert, failure.err
	}
	if failure := generateClientKeyShareSecret(flightCtx.state, flightCtx.cfg); failure != nil {
		return 0, failure.alert, failure.err
	}
	if flightCtx.inboundHandshakeHandler != nil {
		if err := flightCtx.inboundHandshakeHandler(flightCtx.state.CipherSuite, items); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}
	flightCtx.state.HandshakeRecvSequence = seq

	return Flight4, nil, nil
}

func clientHelloCookie(extensions []extension.Extension) []byte {
	for _, ext := range extensions {
		if cookieExt, ok := ext.(*extension.CookieExt); ok {
			return cookieExt.Cookie
		}
	}

	return nil
}

func selectClientKeyShare(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
) bool {
	selectedGroup, ok := preferredClientGroup(state, cfg)
	if !ok {
		return false
	}
	state.SelectedGroup = selectedGroup

	return true
}

func generateClientKeyShareSecret(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
) *clientHelloExtensionFailure {
	selectedGroup, ok := preferredClientGroup(state, cfg)
	if !ok {
		if state.RemoteGroups != nil {
			return newClientHelloExtensionFailure(alert.InsufficientSecurity, dtlserrors.ErrNoSupportedEllipticCurves)
		}

		return nil
	}
	state.SelectedGroup = selectedGroup

	selectedEntry, ok := clientKeyShareForGroup(state, selectedGroup)
	if !ok {
		return newClientHelloExtensionFailure(alert.IllegalParameter, dtlserrors.ErrInvalidClientHello)
	}

	if needsClientKeypair(state) {
		keypair, err := elliptic.GenerateKeypairForPeer(state.SelectedGroup, selectedEntry.KeyExchange)
		if err != nil {
			return newClientHelloExtensionFailure(alert.IllegalParameter, err)
		}
		state.LocalKeypair = keypair
	}

	keyAgreementSecret, err := prf.PreMasterSecret(
		selectedEntry.KeyExchange,
		state.LocalKeypair.PrivateKey,
		state.SelectedGroup,
	)
	if err != nil {
		return newClientHelloExtensionFailure(alert.IllegalParameter, err)
	}
	state.KeyAgreementSecret = keyAgreementSecret

	return nil
}

func matchingClientKeyShare(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
) (extension.KeyShareEntry, bool) {
	selectedGroup, ok := preferredClientGroup(state, cfg)
	if !ok {
		return extension.KeyShareEntry{}, false
	}

	return clientKeyShareForGroup(state, selectedGroup)
}

func preferredClientGroup(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
) (elliptic.Curve, bool) {
	if state.RemoteGroups == nil {
		return 0, false
	}

	for _, group := range cfg.EllipticCurves {
		if slices.Contains(state.RemoteGroups, group) {
			return group, true
		}
	}

	return 0, false
}

func clientKeyShareForGroup(
	state *dtlsstate.State13,
	group elliptic.Curve,
) (extension.KeyShareEntry, bool) {
	if state.RemoteKeyEntries == nil {
		return extension.KeyShareEntry{}, false
	}
	for _, entry := range *state.RemoteKeyEntries {
		if entry.Group == group {
			return entry, true
		}
	}

	return extension.KeyShareEntry{}, false
}

func needsClientKeypair(state *dtlsstate.State13) bool {
	return state.LocalKeypair == nil ||
		state.LocalKeypair.Curve != state.SelectedGroup ||
		state.SelectedGroup == elliptic.X25519MLKEM768
}

func flight2Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	flightCtx.state.HandshakeSendSequence = 0
	if flightCtx.state.CipherSuite == nil {
		return nil, nil, dtlserrors.ErrCipherSuiteUnset
	}

	random := handshake.Random{}
	random.UnmarshalFixed([32]byte(handshake.HelloRetryRequestRandom()))

	exts := []extension.Extension{}

	exts = append(exts, &extension.SupportedVersions{
		Versions:        []protocol.Version{protocol.Version1_3},
		SelectedVersion: true,
	})
	cipherSuiteID := uint16(flightCtx.state.CipherSuite.ID())

	if flightCtx.state.SelectedGroup != 0 {
		exts = append(exts, &extension.KeyShare{
			SelectedGroup: &flightCtx.state.SelectedGroup,
		})
	}

	if len(flightCtx.state.Cookie) > 0 {
		exts = append(exts, &extension.CookieExt{
			Cookie: flightCtx.state.Cookie,
		})
	}

	return []*dtlsflight.Packet{
		{
			Record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageServerHello{
						Version:           protocol.Version1_2,
						Random:            random,
						CipherSuiteID:     &cipherSuiteID,
						CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
						Extensions:        exts,
					},
				},
			},
		},
	}, nil, nil
}

func flight4Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	if flightCtx.state.CipherSuite == nil {
		return nil, nil, dtlserrors.ErrCipherSuiteUnset
	}
	if flightCtx.state.LocalKeypair == nil {
		return nil, nil, dtlserrors.ErrServerKeyShareMissing
	}

	cipherSuiteID := uint16(flightCtx.state.CipherSuite.ID())
	serverHelloExtensions := []extension.Extension{
		&extension.SupportedVersions{
			Versions:        []protocol.Version{protocol.Version1_3},
			SelectedVersion: true,
		},
	}
	serverHelloExtensions = append(serverHelloExtensions, &extension.KeyShare{
		ServerShare: &extension.KeyShareEntry{
			Group:       flightCtx.state.LocalKeypair.Curve,
			KeyExchange: flightCtx.state.LocalKeypair.PublicKey,
		},
	})

	return []*dtlsflight.Packet{
		{
			Record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageServerHello{
						Version:           protocol.Version1_2,
						Random:            flightCtx.state.LocalRandom,
						CipherSuiteID:     &cipherSuiteID,
						CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
						Extensions:        serverHelloExtensions,
					},
				},
			},
		},
		{
			Record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
					Epoch:   EpochHandshake,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageEncryptedExtensions{},
				},
			},
			ShouldEncrypt:            true,
			ResetLocalSequenceNumber: true,
		},
		{
			Record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
					Epoch:   EpochHandshake,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageFinished{},
				},
			},
			ShouldEncrypt: true,
		},
	}, nil, nil
}
