// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"bytes"
	"context"
	"crypto/rand"
	"slices"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls12"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

// renegotiationInfoSCSV is TLS_EMPTY_RENEGOTIATION_INFO_SCSV defined in RFC 5746.
// https://datatracker.ietf.org/doc/html/rfc5746#section-3.3.
const renegotiationInfoSCSV uint16 = 0x00ff

//nolint:cyclop
func flight0Parse(_ context.Context, _ dtlsflight.Conn, state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) (Flight, *alert.Alert, error) {
	pull := cache.FullPullMapItems(0, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},
	)
	if pull.Err != nil {
		return 0, nil, pull.Err
	}
	if !pull.Ready {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	// Connection Identifiers must be negotiated afresh on session resumption.
	// https://datatracker.ietf.org/doc/html/rfc9146#name-the-connection_id-extension
	state.ResetConnectionIDs()

	state.HandshakeRecvSequence = pull.NextSequence

	// Validate type
	clientHello, ok := pull.Messages[handshake.TypeClientHello].(*handshake.MessageClientHello)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if clientHello.Version != protocol.Version1_2 {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlserrors.ErrUnsupportedProtocolVersion
	}

	state.RemoteClientHelloSnapshots.Reset()
	if err := state.RemoteClientHelloSnapshots.RecordWire(pull.Items[0].Raw.Data); err != nil {
		return 0, nil, err
	}

	if !cfg.InsecureSkipHelloVerify {
		return Flight2, nil, nil
	}

	return negotiateClientHello(clientHello, state, cfg, Flight4)
}

//nolint:cyclop
func negotiateClientHello(clientHello *handshake.MessageClientHello, state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, nextFlight Flight) (Flight, *alert.Alert, error) {
	state.RemoteSupportsRenegotiation = false
	state.ExtendedMasterSecret = false
	state.ServerName = ""
	state.PeerSupportedProtocols = nil
	state.RemoteCertSignatureSchemes = nil
	state.LocalKeypair = nil
	state.NamedCurve = 0
	if curves := supportedEllipticCurves(cfg.EllipticCurves); len(curves) > 0 {
		state.NamedCurve = curves[0]
	}
	state.RemoteRandom = clientHello.Random

	cipherSuites := []dtlsconfig.CipherSuite{}
	for _, id := range clientHello.CipherSuiteIDs {
		if id == renegotiationInfoSCSV {
			state.RemoteSupportsRenegotiation = true

			continue
		}
		if c, found := dtlsflight.FindCipherSuiteByID(id, cfg.LocalCipherSuites); found && c.Capabilities().SupportsVersion(protocol.Version1_2) {
			cipherSuites = append(cipherSuites, c)
		}
	}

	var ok bool
	if state.CipherSuite, ok = dtlsflight.FindMatchingCipherSuite(cipherSuites, cfg.LocalCipherSuites); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrCipherSuiteNoIntersection
	}

	var offeredGroups []elliptic.Curve
	var sawGroups bool
	for _, val := range clientHello.Extensions {
		switch ext := val.(type) {
		case *extension.SupportedGroups:
			sawGroups = true
			offeredGroups = ext.Groups
		case *extension12.ExtendedMasterSecret:
			if cfg.ExtendedMasterSecret != dtlsconfig.DisableExtendedMasterSecret {
				state.ExtendedMasterSecret = true
			}
		case *extension.ServerNameOffer:
			state.ServerName = ext.ServerName // remote server name
		case *extension12.RenegotiationInfo:
			state.RemoteSupportsRenegotiation = true
		case *extension.ALPNOffer:
			state.PeerSupportedProtocols = slices.Clone(ext.Protocols)
		case *extension.CertificateSignatureAlgorithms:
			// Store the client's certificate signature schemes for later validation
			state.RemoteCertSignatureSchemes = dtlsflight.SignatureSchemes(ext.Schemes)
		}
	}

	if state.CipherSuite.AuthenticationType() == cryptosuite.AuthenticationTypeCertificate {
		offeredIDs := make([]cryptosuite.ID, len(cipherSuites))
		for i, suite := range cipherSuites {
			offeredIDs[i] = suite.ID()
		}
		certificate, err := cfg.GetCertificate(&dtlsconfig.ClientHelloInfo{
			ServerName: state.ServerName, CipherSuites: offeredIDs, RandomBytes: state.RemoteRandom.RandomBytes, Hello: clientHello,
		})
		if err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
		}
		state.ServerCertificate = certificate
		usable := dtlsconfig.FilterCipherSuitesForCertificate(certificate, cfg.LocalCipherSuites)
		if state.CipherSuite, ok = dtlsflight.FindMatchingCipherSuite(cipherSuites, usable); !ok {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrCipherSuiteNoIntersection
		}
	}

	if cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret && !state.ExtendedMasterSecret {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrServerRequiredButNoClientEMS
	}

	flight, resumeAlert, err := handleHelloResume(clientHello.SessionID, state, cfg, nextFlight)
	if err != nil || resumeAlert != nil {
		return flight, resumeAlert, err
	}
	if flight != Flight4b && state.CipherSuite.KeyExchangeAlgorithm().Has(cryptosuite.KeyExchangeAlgorithmEcdhe) {
		if fallback := selectNonECDHEFallback(cfg, cipherSuites, offeredGroups, sawGroups); fallback != nil {
			state.CipherSuite = fallback

			return flight, nil, nil
		}
		if dtlsAlert, err := selectAcceptCurve(state, cfg, offeredGroups, sawGroups); err != nil {
			return 0, dtlsAlert, err
		}
	}

	return flight, nil, nil
}

//nolint:cyclop // Validate cached authentication and negotiation before installing keys.
func handleHelloResume(
	sessionID []byte,
	state *dtlsstate.State12,
	cfg *dtlsconfig.HandshakeConfig,
	next Flight,
) (Flight, *alert.Alert, error) {
	if next == Flight2 || len(sessionID) == 0 || !cfg.HasSessionStore {
		return next, nil, nil
	}
	session, err := cfg.GetSession(sessionID)
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if !cfg.UsableSession(session, false) || !bytes.Equal(session.ID, sessionID) {
		return next, nil, nil
	}
	// RFC 7627 section 5.3 requires aborting an EMS session's
	// abbreviated handshake when the client omits the extension.
	if session.ExtendedMasterSecret && !state.ExtendedMasterSecret {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrSessionEMSMismatch
	}
	if session.CipherSuiteID != state.CipherSuite.ID() || session.ExtendedMasterSecret != state.ExtendedMasterSecret {
		return next, nil, nil
	}
	cfg.Log.Tracef("[handshake] resume session: %x", sessionID)

	state.SessionID = sessionID
	state.MasterSecret = session.Secret
	state.IdentityHint = bytes.Clone(session.IdentityHint)
	state.PeerCertificates = session.PeerCertificates

	if err := state.InitCipherSuite(); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	clientRandom := state.LocalRandom.MarshalFixed()
	cfg.WriteKeyLog(keyLogLabel, clientRandom[:], state.MasterSecret)

	return Flight4b, nil, nil
}

func flight0Generate(_ dtlsflight.Conn, state *dtlsstate.State12, _ *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	// Initialize
	state.SetSRTPProtectionProfile(0)
	if !cfg.InsecureSkipHelloVerify {
		state.Cookie = make([]byte, cookieLength)
		if _, err := rand.Read(state.Cookie); err != nil {
			return nil, nil, err
		}
	}

	var zeroEpoch uint64
	state.SetLocalEpoch(zeroEpoch)
	state.SetRemoteEpoch(zeroEpoch)
	ellipticCurves := supportedEllipticCurves(cfg.EllipticCurves)
	if len(ellipticCurves) == 0 {
		return nil, nil, dtlserrors.ErrEmptyEllipticCurves
	}
	state.NamedCurve = ellipticCurves[0]

	if err := state.LocalRandom.Populate(); err != nil {
		return nil, nil, err
	}

	return nil, nil, nil
}

func selectNonECDHEFallback(
	cfg *dtlsconfig.HandshakeConfig, suites []dtlsconfig.CipherSuite, offered []elliptic.Curve, offeredPresent bool,
) dtlsconfig.CipherSuite {
	if !offeredPresent {
		return nil
	}
	if _, shared := selectEllipticCurve(supportedEllipticCurves(cfg.EllipticCurves), offered); shared {
		return nil
	}

	usable := slices.DeleteFunc(slices.Clone(suites), func(suite dtlsconfig.CipherSuite) bool {
		return suite.KeyExchangeAlgorithm().Has(cryptosuite.KeyExchangeAlgorithmEcdhe)
	})
	fallback, _ := dtlsflight.FindMatchingCipherSuite(usable, cfg.LocalCipherSuites)

	return fallback
}

func selectAcceptCurve(
	state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, offered []elliptic.Curve, offeredPresent bool,
) (*alert.Alert, error) {
	if offeredPresent && len(offered) == 0 {
		return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrNoSupportedEllipticCurves
	}

	if len(offered) > 0 {
		namedCurve, ok := selectEllipticCurve(supportedEllipticCurves(cfg.EllipticCurves), offered)
		if !ok {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrNoSupportedEllipticCurves
		}
		state.NamedCurve = namedCurve
	}

	if state.LocalKeypair == nil {
		keypair, err := elliptic.GenerateKeypair(state.NamedCurve)
		if err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
		}
		state.LocalKeypair = keypair
	}

	return nil, nil //nolint:nilnil // no alert or error
}
