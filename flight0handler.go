// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
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

	helloHash, err := clientHelloNegotiationHash(clientHello)
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
	}
	state.initialClientHelloHash = helloHash
	nextFlight := flight2
	if cfg.insecureSkipHelloVerify {
		nextFlight = flight4
	}
	if nextFlight == flight2 {
		return flight2, nil, nil
	}

	return negotiateClientHello(clientHello, state, cfg, nextFlight)
}

//nolint:cyclop,gocognit,gocyclo
func negotiateClientHello(
	clientHello *handshake.MessageClientHello, state *State, cfg *handshakeConfig, nextFlight flightVal,
) (flightVal, *alert.Alert, error) {
	// Discard every negotiation result from the previous ClientHello. The first
	// ClientHello is excluded from the authenticated handshake transcript.
	state.remoteSupportsRenegotiation = false
	state.setSRTPProtectionProfile(0)
	state.remoteSRTPMasterKeyIdentifier = nil
	state.extendedMasterSecret = false
	state.serverName = ""
	state.peerSupportedProtocols = nil
	state.setLocalConnectionID(nil)
	state.remoteConnectionID = nil
	state.remoteCertSignatureSchemes = nil
	state.localKeypair = nil
	state.namedCurve = cfg.ellipticCurves[0]
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

	var ok bool
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
			// Defer curve validation until we know whether key exchange is needed.
			sawSupportedGroups = true
			offeredEllipticCurves = ext.EllipticCurves
		case *extension.UseSRTP:
			profile, found := findMatchingSRTPProfile(cfg.localSRTPProtectionProfiles, ext.ProtectionProfiles)
			if !found {
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
	if state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate {
		offeredIDs := make([]CipherSuiteID, len(cipherSuites))
		for i, suite := range cipherSuites {
			offeredIDs[i] = suite.ID()
		}
		certificate, err := cfg.getCertificate(&ClientHelloInfo{
			ServerName: state.serverName, CipherSuites: offeredIDs, RandomBytes: state.remoteRandom.RandomBytes,
		})
		if err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
		}
		state.serverCertificate = certificate
		usable := filterCipherSuitesForCertificate(certificate, cfg.localCipherSuites)
		if state.cipherSuite, ok = findMatchingCipherSuite(cipherSuites, usable); !ok {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, errCipherSuiteNoIntersection
		}
	}

	if cfg.extendedMasterSecret == RequireExtendedMasterSecret && !state.extendedMasterSecret {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errServerRequiredButNoClientEMS
	}

	flight, resumeAlert, err := handleHelloResume(clientHello.SessionID, state, cfg, nextFlight)
	if err != nil || resumeAlert != nil {
		return flight, resumeAlert, err
	}

	// Resumed sessions and plain PSK do not need a curve.
	if flight != flight4b && state.cipherSuite.KeyExchangeAlgorithm().Has(CipherSuiteKeyExchangeAlgorithmEcdhe) {
		if fallback := selectNonECDHEFallback(cfg, cipherSuites, offeredEllipticCurves, sawSupportedGroups); fallback != nil {
			state.cipherSuite = fallback

			return flight, nil, nil
		}
		if alertPtr, err := selectAcceptCurve(state, cfg, offeredEllipticCurves, sawSupportedGroups); err != nil {
			return 0, alertPtr, err
		}
	}

	return flight, nil, nil
}

// selectNonECDHEFallback retries suite selection only when no offered group is shared.
func selectNonECDHEFallback(
	cfg *handshakeConfig, suites []CipherSuite, offered []elliptic.Curve, offeredPresent bool,
) CipherSuite {
	if !offeredPresent {
		return nil
	}
	if _, shared := selectEllipticCurve(cfg.ellipticCurves, offered); shared {
		return nil
	}

	usable := slices.DeleteFunc(slices.Clone(suites), func(suite CipherSuite) bool {
		return suite.KeyExchangeAlgorithm().Has(CipherSuiteKeyExchangeAlgorithmEcdhe)
	})
	fallback, _ := findMatchingCipherSuite(usable, cfg.localCipherSuites)

	return fallback
}

// selectAcceptCurve selects a curve and generates a keypair for fresh ECDHE.
// Absent supported_groups keeps the default (RFC 8422 §5.1); a present but
// empty list, including one whose unknown IDs were dropped, must be rejected.
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

	return nil, nil //nolint:nilnil // no alert or error
}

// selectEllipticCurve returns the first shared curve in client preference order.
func selectEllipticCurve(configured, offered []elliptic.Curve) (elliptic.Curve, bool) {
	for _, curve := range offered {
		if slices.Contains(configured, curve) {
			return curve, true
		}
	}

	return 0, false
}

//nolint:cyclop // Check cached authentication and negotiation before installing the session.
func handleHelloResume(
	sessionID []byte,
	state *State,
	cfg *handshakeConfig,
	next flightVal,
) (flightVal, *alert.Alert, error) {
	if next == flight2 || len(sessionID) == 0 || cfg.sessionStore == nil {
		return next, nil, nil
	}
	session, err := cfg.sessionStore.Get(sessionID)
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if !session.usable(cfg, false) || !bytes.Equal(session.ID, sessionID) {
		return next, nil, nil
	}
	// RFC 7627 section 5.3 requires aborting an EMS session's
	// abbreviated handshake when the client omits the extension.
	if session.ExtendedMasterSecret && !state.extendedMasterSecret {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, errSessionEMSMismatch
	}
	if session.CipherSuiteID != state.cipherSuite.ID() || session.ExtendedMasterSecret != state.extendedMasterSecret {
		return next, nil, nil
	}
	cfg.log.Tracef("[handshake] resume session: %x", sessionID)

	state.SessionID = sessionID
	state.masterSecret = session.Secret
	state.IdentityHint = bytes.Clone(session.IdentityHint)
	state.PeerCertificates = session.PeerCertificates

	if err := state.initCipherSuite(); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	clientRandom := state.localRandom.MarshalFixed()
	cfg.writeKeyLog(keyLogLabelTLS12, clientRandom[:], state.masterSecret)

	return flight4b, nil, nil
}

func flight0Generate(
	_ flightConn,
	state *State,
	_ *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *alert.Alert, error) {
	// Initialize
	state.clientKeyExchange = nil
	state.clientFlightProcessed = false
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
