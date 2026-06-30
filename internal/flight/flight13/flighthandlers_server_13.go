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

type clientHello13ExtensionSet struct {
	hasPreSharedKey        bool
	hasSignatureAlgorithms bool
	hasSupportedGroups     bool
}

type clientHello13ExtensionFailure struct {
	alert *alert.Alert
	err   error
}

func newClientHello13ExtensionFailure(
	description alert.Description,
	err error,
) *clientHello13ExtensionFailure {
	return &clientHello13ExtensionFailure{
		alert: &alert.Alert{Level: alert.Fatal, Description: description},
		err:   err,
	}
}

func processClientHello13Extensions(
	state *dtlsstate.State,
	cfg *dtlsconfig.HandshakeConfig,
	clientHello *handshake.MessageClientHello,
) *clientHello13ExtensionFailure {
	var seen clientHello13ExtensionSet

	for _, val := range clientHello.Extensions {
		if failure := processClientHello13SecurityExtension(state, cfg, &seen, val); failure != nil {
			return failure
		}
		processClientHello13StateExtension(state, cfg, val)
	}

	if !seen.hasPreSharedKey && (!seen.hasSignatureAlgorithms || !seen.hasSupportedGroups) {
		return newClientHello13ExtensionFailure(alert.MissingExtension, dtlserrors.ErrMissingClientHelloExtension)
	}

	return nil
}

func processClientHello13SecurityExtension(
	state *dtlsstate.State,
	cfg *dtlsconfig.HandshakeConfig,
	seen *clientHello13ExtensionSet,
	val extension.Extension,
) *clientHello13ExtensionFailure {
	switch ext := val.(type) {
	case *extension.SupportedEllipticCurves:
		seen.hasSupportedGroups = true
		if len(ext.EllipticCurves) == 0 {
			return newClientHello13ExtensionFailure(alert.InsufficientSecurity, dtlserrors.ErrNoSupportedEllipticCurves)
		}
		state.RemoteGroups = ext.EllipticCurves
	case *extension.UseSRTP:
		profile, ok := dtlsflight.FindMatchingSRTPProfile(cfg.LocalSRTPProtectionProfiles, ext.ProtectionProfiles)
		if !ok {
			return newClientHello13ExtensionFailure(alert.InsufficientSecurity, dtlserrors.ErrServerNoMatchingSRTPProfile)
		}
		state.SetSRTPProtectionProfile(profile)
		state.RemoteSRTPMasterKeyIdentifier = ext.MasterKeyIdentifier
	case *extension.SupportedSignatureAlgorithms:
		seen.hasSignatureAlgorithms = true
		state.RemoteSignatureSchemes = ext.SignatureHashAlgorithms
	case *extension.SupportedVersions:
		if ext.IsSelectedVersion() {
			return newClientHello13ExtensionFailure(alert.IllegalParameter, dtlserrors.ErrInvalidClientHello)
		}
		state.RemoteVersions = ext.Versions
	case *extension.PreSharedKey:
		seen.hasPreSharedKey = true
	}

	return nil
}

func processClientHello13StateExtension(
	state *dtlsstate.State,
	cfg *dtlsconfig.HandshakeConfig,
	val extension.Extension,
) {
	switch ext := val.(type) {
	case *extension.UseExtendedMasterSecret:
		if cfg.ExtendedMasterSecret != dtlsconfig.DisableExtendedMasterSecret {
			state.ExtendedMasterSecret = true
		}
	case *extension.ServerName:
		state.ServerName = ext.ServerName // remote server name
	case *extension.RenegotiationInfo:
		state.RemoteSupportsRenegotiation = true
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

//nolint:cyclop,gocognit,gocyclo,unused
func flight13_0Parse(
	_ context.Context,
	_ dtlsflight.Conn,
	flightCtx *handshakeContext13,
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
			state.RemoteSupportsRenegotiation = true

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

	if failure := processClientHello13Extensions(state, cfg, clientHello); failure != nil {
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

	if cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret && !state.ExtendedMasterSecret {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrServerRequiredButNoClientEMS //nolint:lll
	}

	nextFlight := Flight2

	// nolint:nestif
	if state.RemoteKeyEntries != nil && state.RemoteGroups != nil {
		// Overlapping groups between client and server
		var groups []elliptic.Curve
		for _, group := range state.RemoteGroups {
			if slices.Contains(cfg.EllipticCurves, group) {
				groups = append(groups, group)
			}
		}
		// Find key entry group in supported groups by client and server
		foundEntry := false
		for _, entry := range *state.RemoteKeyEntries {
			if slices.Contains(groups, entry.Group) {
				state.NamedCurve = entry.Group
				foundEntry = true
				// Ensure that first matching entry is chosen
				break
			}
		}
		if foundEntry && (state.LocalKeypair == nil || state.LocalKeypair.Curve != state.NamedCurve) {
			var err error
			state.LocalKeypair, err = elliptic.GenerateKeypair(state.NamedCurve)
			if err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
			}
		}
	}

	if cfg.InsecureSkipHelloVerify {
		nextFlight = Flight4
	}

	if flightCtx.inboundHandshakeHandler != nil {
		if err := flightCtx.inboundHandshakeHandler(state.CipherSuite, items); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	return nextFlight, nil, nil
}

// nolint:unparam
func flight13_0Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext13,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	state := flightCtx.state
	cfg := flightCtx.cfg

	if !cfg.InsecureSkipHelloVerify {
		state.Cookie = make([]byte, cookieLength)
		if _, err := rand.Read(state.Cookie); err != nil {
			return nil, nil, err
		}
	}

	var zeroEpoch uint16
	state.LocalEpoch.Store(zeroEpoch)
	state.RemoteEpoch.Store(zeroEpoch)
	if len(cfg.EllipticCurves) < 1 {
		return nil, nil, dtlserrors.ErrEmptyEllipticCurves
	}

	if err := state.LocalRandom.Populate(); err != nil {
		return nil, nil, err
	}

	return nil, nil, nil
}

func flight13_2Parse(
	_ context.Context,
	_ dtlsflight.Conn,
	flightCtx *handshakeContext13,
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

	cookie := clientHello13Cookie(clientHello.Extensions)

	if len(cookie) == 0 {
		return 0, nil, nil
	}
	if !bytes.Equal(flightCtx.state.Cookie, cookie) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.AccessDenied}, dtlserrors.ErrCookieMismatch
	}

	if failure := processClientHello13Extensions(flightCtx.state, flightCtx.cfg, clientHello); failure != nil {
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

func clientHello13Cookie(extensions []extension.Extension) []byte {
	for _, ext := range extensions {
		if cookieExt, ok := ext.(*extension.CookieExt); ok {
			return cookieExt.Cookie
		}
	}

	return nil
}

func flight13_2Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext13,
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

	if flightCtx.state.NamedCurve != 0 {
		exts = append(exts, &extension.KeyShare{
			SelectedGroup: &flightCtx.state.NamedCurve,
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

func flight13_4Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext13,
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
					Epoch:   1,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageEncryptedExtensions{},
				},
			},
			ShouldEncrypt:            true,
			ResetLocalSequenceNumber: true,
		},
	}, nil, nil
}
