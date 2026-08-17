// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

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
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// renegotiationInfoSCSV is TLS_EMPTY_RENEGOTIATION_INFO_SCSV defined in RFC 5746.
// https://datatracker.ietf.org/doc/html/rfc5746#section-3.3.
const renegotiationInfoSCSV uint16 = 0x00ff

//nolint:cyclop,gocognit,gocyclo
func flight0Parse(
	_ context.Context,
	_ dtlsflight.Conn,
	state *dtlsstate.State12,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (Flight, *alert.Alert, error) {
	pull := cache.FullPullMapItems(0, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false}, //nolint:lll
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

	filteredCipherSuites := cipherSuites[:0]
	for _, cipherSuite := range cipherSuites {
		if ciphersuite.IDSupportsVersion(cipherSuite.ID(), protocol.Version1_2) {
			filteredCipherSuites = append(filteredCipherSuites, cipherSuite)
		}
	}
	cipherSuites = filteredCipherSuites

	if state.CipherSuite, ok = dtlsflight.FindMatchingCipherSuite(cipherSuites, cfg.LocalCipherSuites); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrCipherSuiteNoIntersection //nolint:lll
	}

	for _, val := range clientHello.Extensions {
		switch ext := val.(type) {
		case *extension.SupportedGroups:
			if len(ext.Groups) == 0 {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrNoSupportedEllipticCurves //nolint:lll
			}
			namedCurve, ok := selectEllipticCurve(cfg.EllipticCurves, ext.Groups)
			if !ok {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrNoSupportedEllipticCurves //nolint:lll
			}
			state.NamedCurve = namedCurve
		case *extension.SRTPOffer:
			profile, ok := dtlsflight.FindMatchingSRTPProfile(cfg.LocalSRTPProtectionProfiles, ext.ProtectionProfiles)
			if !ok {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrServerNoMatchingSRTPProfile //nolint:lll
			}
			state.SetSRTPProtectionProfile(profile)
			state.RemoteSRTPMasterKeyIdentifier = bytes.Clone(ext.MasterKeyIdentifier)
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

	if cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret && !state.ExtendedMasterSecret {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrServerRequiredButNoClientEMS //nolint:lll
	}

	if state.LocalKeypair == nil {
		var err error
		state.LocalKeypair, err = elliptic.GenerateKeypair(state.NamedCurve)
		if err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
		}
	}

	state.RemoteClientHelloSnapshots.Reset()
	if err := state.RemoteClientHelloSnapshots.RecordWire(pull.Items[0].Raw.Data); err != nil {
		return 0, nil, err
	}

	nextFlight := Flight2

	if cfg.InsecureSkipHelloVerify {
		nextFlight = Flight4
	}

	return handleHelloResume(clientHello.SessionID, state, cfg, nextFlight)
}

func handleHelloResume(
	sessionID []byte,
	state *dtlsstate.State12,
	cfg *dtlsconfig.HandshakeConfig,
	next Flight,
) (Flight, *alert.Alert, error) {
	if len(sessionID) > 0 && cfg.HasSessionStore {
		if id, secret, err := cfg.GetSession(sessionID); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		} else if id != nil {
			cfg.Log.Tracef("[handshake] resume session: %x", sessionID)

			state.SessionID = sessionID
			state.MasterSecret = secret

			if err := state.InitCipherSuite(); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}

			clientRandom := state.LocalRandom.MarshalFixed()
			cfg.WriteKeyLog(keyLogLabel, clientRandom[:], state.MasterSecret)

			return Flight4b, nil, nil
		}
	}

	return next, nil, nil
}

func flight0Generate(
	_ dtlsflight.Conn,
	state *dtlsstate.State12,
	_ *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	// Initialize
	if !cfg.InsecureSkipHelloVerify {
		state.Cookie = make([]byte, cookieLength)
		if _, err := rand.Read(state.Cookie); err != nil {
			return nil, nil, err
		}
	}

	var zeroEpoch uint16
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
