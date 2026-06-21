// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto/rand"
	"slices"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
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

//nolint:cyclop,gocognit,gocyclo,unused
func flight13_0Parse(
	_ context.Context,
	_ flightConn,
	flightCtx *handshakeContext13,
) (flightVal13, *alert.Alert, error) {
	state := flightCtx.state
	cache := flightCtx.cache
	cfg := flightCtx.cfg

	if state.localVersion != protocol.Version1_3 {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, errInvalidProtocolVersionState
	}
	seq, msgs, ok := cache.fullPullMap(0, state.cipherSuite,
		handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	// Connection Identifiers must be negotiated afresh on session resumption.
	// https://datatracker.ietf.org/doc/html/rfc9146#name-the-connection_id-extension
	state.setLocalConnectionID(nil)
	state.remoteConnectionID = nil

	state.handshakeRecvSequence = seq

	var clientHello *handshake.MessageClientHello

	// Validate type
	if clientHello, ok = msgs[handshake.TypeClientHello].(*handshake.MessageClientHello); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if !clientHello.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, errUnsupportedProtocolVersion
	}

	state.remoteRandom = clientHello.Random

	cipherSuites := []CipherSuite{}
	for _, id := range clientHello.CipherSuiteIDs {
		if id == renegotiationInfoSCSV {
			state.remoteSupportsRenegotiation = true

			continue
		}
		if c := cipherSuiteForID(CipherSuiteID(id), cfg.customCipherSuites); c != nil {
			cipherSuites = append(cipherSuites, c)
		}
	}

	// nolint:godox
	// TODO: check for DTLS 1.3 cipher suites
	if state.cipherSuite, ok = findMatchingCipherSuite(cipherSuites, cfg.localCipherSuites); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errCipherSuiteNoIntersection
	}

	for _, val := range clientHello.Extensions {
		switch ext := val.(type) {
		case *extension.SupportedEllipticCurves:
			if len(ext.EllipticCurves) == 0 {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errNoSupportedEllipticCurves
			}
			state.remoteGroups = ext.EllipticCurves
		case *extension.UseSRTP:
			profile, ok := findMatchingSRTPProfile(cfg.localSRTPProtectionProfiles, ext.ProtectionProfiles)
			if !ok {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errServerNoMatchingSRTPProfile
			}
			state.setSRTPProtectionProfile(profile)
			state.remoteSRTPMasterKeyIdentifier = ext.MasterKeyIdentifier
		case *extension.UseExtendedMasterSecret:
			if cfg.extendedMasterSecret != DisableExtendedMasterSecret {
				state.extendedMasterSecret = true
			}
		case *extension.ServerName:
			state.serverName = ext.ServerName // remote server name
		case *extension.RenegotiationInfo:
			state.remoteSupportsRenegotiation = true
		case *extension.ALPN:
			state.peerSupportedProtocols = ext.ProtocolNameList
		case *extension.ConnectionID:
			// Only set connection ID to be sent if server supports connection
			// IDs.
			if cfg.connectionIDGenerator != nil {
				state.remoteConnectionID = ext.CID
			}
		case *extension.SignatureAlgorithmsCert:
			// Store the client's certificate signature schemes for later validation
			state.remoteCertSignatureSchemes = ext.SignatureHashAlgorithms
		case *extension.SupportedVersions:
			state.remoteVersions = ext.Versions
		case *extension.KeyShare:
			state.remoteKeyEntries = &ext.ClientShares
		}
	}

	if !slices.Contains(state.remoteVersions, protocol.Version1_3) {
		// nolint:godox
		// TODO: This should actually handover the state machine to DTLS 1.2
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, errInvalidProtocolVersionState
	}

	// If the client doesn't support connection IDs, the server should not
	// expect one to be sent.
	if state.remoteConnectionID == nil {
		state.setLocalConnectionID(nil)
	}

	if cfg.extendedMasterSecret == RequireExtendedMasterSecret && !state.extendedMasterSecret {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errServerRequiredButNoClientEMS
	}

	nextFlight := flight13_2

	// nolint:nestif
	if state.remoteKeyEntries != nil && state.remoteGroups != nil {
		// Overlapping groups between client and server
		var groups []elliptic.Curve
		for _, group := range state.remoteGroups {
			if slices.Contains(cfg.ellipticCurves, group) {
				groups = append(groups, group)
			}
		}
		// Find key entry group in supported groups by client and server
		foundEntry := false
		for _, entry := range *state.remoteKeyEntries {
			if slices.Contains(groups, entry.Group) {
				state.namedCurve = entry.Group
				foundEntry = true
				// Ensure that first matching entry is chosen
				break
			}
		}
		if foundEntry && (state.localKeypair == nil || state.localKeypair.Curve != state.namedCurve) {
			var err error
			state.localKeypair, err = elliptic.GenerateKeypair(state.namedCurve)
			if err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
			}
		}
	}

	if cfg.insecureSkipHelloVerify {
		nextFlight = flight13_4
	}

	return nextFlight, nil, nil
}

// nolint:unparam
func flight13_0Generate(
	_ flightConn,
	flightCtx *handshakeContext13,
) ([]*packet, *alert.Alert, error) {
	state := flightCtx.state
	cfg := flightCtx.cfg

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

	if err := state.localRandom.Populate(); err != nil {
		return nil, nil, err
	}

	return nil, nil, nil
}
