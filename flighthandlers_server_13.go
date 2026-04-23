// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"slices"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
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

//nolint:cyclop,gocognit
func flight13_0Parse(
	_ context.Context,
	_ flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal13, *alert.Alert, error) {
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

	// Check for DTLS 1.3 cipher suites?
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
			state.remoteKeyEntries = ext.ClientShares
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

	if state.localKeypair == nil {
		var err error
		state.localKeypair, err = elliptic.GenerateKeypair(state.namedCurve)
		if err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
		}
	}

	nextFlight := flight13_2

	var groups []elliptic.Curve
	for _, entry := range state.remoteKeyEntries {
		// Clients MUST NOT offer any KeyShareEntry values
		// for groups not listed in the client's "supported_groups" extension.
		// Servers MAY check for violations of these rules and abort the
		// handshake with an "illegal_parameter" alert if one is violated.
		if !slices.Contains(state.remoteGroups, entry.Group) {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, errInvalidGroupInKeyShare
		}
		groups = append(groups, entry.Group)
	}
	state.namedCurve, _ = findMatchingGroup(groups, cfg.ellipticCurves)

	if cfg.insecureSkipHelloVerify {
		nextFlight = flight13_4
	}

	return nextFlight, nil, nil
}
