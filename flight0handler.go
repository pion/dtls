// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
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

// renegotiationInfoSCSV is TLS_EMPTY_RENEGOTIATION_INFO_SCSV defined in RFC 5746.
// https://datatracker.ietf.org/doc/html/rfc5746#section-3.3.
const renegotiationInfoSCSV uint16 = 0x00ff

//nolint:cyclop,gocognit
func flight0Parse(
	_ context.Context,
	_ flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *alert.Alert, error) {
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

	if state.cipherSuite, ok = findMatchingCipherSuite(cipherSuites, cfg.localCipherSuites); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errCipherSuiteNoIntersection
	}

	var (
		offeredEllipticCurves []elliptic.Curve
		sawSupportedGroups    bool
	)
	for _, val := range clientHello.Extensions {
		switch ext := val.(type) {
		case *extension.SupportedEllipticCurves:
			// Record the client's offered curves (and that it offered the
			// extension at all). Selection and validation are deferred to the
			// non-resumption, ECDHE path below: only ECDHE key exchange uses a
			// curve, so validating here would wrongly reject session resumption
			// and plain-PSK handshakes, which use none.
			sawSupportedGroups = true
			offeredEllipticCurves = ext.EllipticCurves
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
		}
	}

	// If the client doesn't support connection IDs, the server should not
	// expect one to be sent.
	if state.remoteConnectionID == nil {
		state.setLocalConnectionID(nil)
	}

	if cfg.extendedMasterSecret == RequireExtendedMasterSecret && !state.extendedMasterSecret {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errServerRequiredButNoClientEMS
	}

	nextFlight := flight2

	if cfg.insecureSkipHelloVerify {
		nextFlight = flight4
	}

	flight, resumeAlert, err := handleHelloResume(clientHello.SessionID, state, cfg, nextFlight)
	if err != nil || resumeAlert != nil {
		return flight, resumeAlert, err
	}

	// handleHelloResume returns flight4b only when the session resumed; a resumed
	// session reuses cached crypto and performs no key exchange, and only ECDHE
	// uses a curve. Select/validate the negotiated curve (and generate the server
	// keypair) only on the non-resumption ECDHE path, so that a server restricting
	// its configured EllipticCurves cannot wrongly reject session resumption or a
	// plain-PSK handshake, which use no curve.
	if flight != flight4b && state.cipherSuite.KeyExchangeAlgorithm().Has(CipherSuiteKeyExchangeAlgorithmEcdhe) {
		if _, sharedCurve := selectEllipticCurve(cfg.ellipticCurves, offeredEllipticCurves); sawSupportedGroups && !sharedCurve {
			// A fresh ECDHE handshake needs a shared group. Retry with the
			// remaining suites, preserving the client's preference order.
			usableSuites := slices.DeleteFunc(slices.Clone(cipherSuites), func(suite CipherSuite) bool {
				return suite.KeyExchangeAlgorithm().Has(CipherSuiteKeyExchangeAlgorithmEcdhe)
			})
			if fallback, found := findMatchingCipherSuite(usableSuites, cfg.localCipherSuites); found {
				state.cipherSuite = fallback

				return flight, nil, nil
			}
		}
		if alertPtr, err := selectAcceptCurve(state, cfg, offeredEllipticCurves, sawSupportedGroups); err != nil {
			return 0, alertPtr, err
		}
	}

	return flight, nil, nil
}

// selectAcceptCurve negotiates the server's elliptic curve on the non-resumed
// ECDHE accept path and generates the server keypair. Behavior depends on what
// the client advertised in supported_groups:
//   - a set the server also supports: select the intersection, honoring the
//     client's preference order;
//   - a set with no server-supported curve (offeredPresent, but empty after the
//     extension parser drops curve IDs the server does not implement): refuse,
//     since the peers share no curve, rather than fall back to one never offered;
//   - nothing at all: keep the server's default curve (set in flight0Generate),
//     as RFC 8422 §5.1 permits.
//
// The caller must invoke this only for a non-resumed ECDHE handshake.
func selectAcceptCurve(
	state *State, cfg *handshakeConfig, offered []elliptic.Curve, offeredPresent bool,
) (*alert.Alert, error) {
	if offeredPresent && len(offered) == 0 {
		return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errNoSupportedEllipticCurves
	}

	if len(offered) > 0 {
		namedCurve, ok := selectEllipticCurve(cfg.ellipticCurves, offered)
		if !ok {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errNoSupportedEllipticCurves
		}
		state.namedCurve = namedCurve
	}

	if state.localKeypair == nil {
		keypair, err := elliptic.GenerateKeypair(state.namedCurve)
		if err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
		}
		state.localKeypair = keypair
	}

	return nil, nil //nolint:nilnil // two-value (alert, error) status, consistent with this handler
}

// selectEllipticCurve returns the first curve the client offered that the server
// is also configured to use, honoring the client's preference order. It reports
// ok=false when the two lists do not intersect, so the caller refuses the
// handshake instead of falling back to a curve the server never advertised.
//
// This brings elliptic-curve negotiation in line with the cipher-suite and SRTP
// selection in flight0Parse (findMatchingCipherSuite / findMatchingSRTPProfile),
// and with the offer side, which already restricts curves to the configured set.
// Previously the server used the client's first offered curve unconditionally —
// the only handshake parameter that ignored the server's own configuration.
func selectEllipticCurve(configured, offered []elliptic.Curve) (elliptic.Curve, bool) {
	for _, curve := range offered {
		if slices.Contains(configured, curve) {
			return curve, true
		}
	}

	return 0, false
}

func handleHelloResume(
	sessionID []byte,
	state *State,
	cfg *handshakeConfig,
	next flightVal,
) (flightVal, *alert.Alert, error) {
	if len(sessionID) > 0 && cfg.sessionStore != nil {
		if s, err := cfg.sessionStore.Get(sessionID); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		} else if s.ID != nil {
			cfg.log.Tracef("[handshake] resume session: %x", sessionID)

			state.SessionID = sessionID
			state.masterSecret = s.Secret

			if err := state.initCipherSuite(); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}

			clientRandom := state.localRandom.MarshalFixed()
			cfg.writeKeyLog(keyLogLabelTLS12, clientRandom[:], state.masterSecret)

			return flight4b, nil, nil
		}
	}

	return next, nil, nil
}

func flight0Generate(
	_ flightConn,
	state *State,
	_ *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *alert.Alert, error) {
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
