// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"bytes"
	"context"
	"slices"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

//nolint:gocognit,gocyclo,maintidx,cyclop
func flight3Parse(
	ctx context.Context,
	conn dtlsflight.Conn,
	state *dtlsstate.State12,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (next Flight, dtlsAlert *alert.Alert, err error) {
	// Clients may receive multiple HelloVerifyRequest messages with different cookies.
	// Clients SHOULD handle this by sending a new ClientHello with a cookie in response
	// to the new HelloVerifyRequest. RFC 6347 Section 4.2.1
	serverResponsePull := cache.FullPullMapOneOfItems(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeHelloVerifyRequest, Epoch: cfg.InitialEpoch, IsClient: false}, //nolint:lll
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false},        //nolint:lll
	)
	if serverResponsePull.Err != nil {
		return 0, nil, serverResponsePull.Err
	}
	if !serverResponsePull.Ready {
		// Don't have enough messages. Keep reading
		return 0, nil, nil
	}
	serverResponse := serverResponsePull.Messages[handshake.TypeHelloVerifyRequest]
	h, hasHelloVerifyRequest := serverResponse.(*handshake.MessageHelloVerifyRequest)
	if hasHelloVerifyRequest {
		// DTLS 1.2 clients must not assume that the server will use the protocol version
		// specified in HelloVerifyRequest message. RFC 6347 Section 4.2.1
		if !h.Version.Equal(protocol.Version1_0) && !h.Version.Equal(protocol.Version1_2) {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlserrors.ErrUnsupportedProtocolVersion //nolint:lll
		}
		state.Cookie = bytes.Clone(h.Cookie)
		state.HasHelloVerifyRequest = true
		state.HandshakeRecvSequence = serverResponsePull.NextSequence

		return Flight3, nil, nil
	}

	serverResponse = serverResponsePull.Messages[handshake.TypeServerHello]
	serverHelloMsg, hasServerHello := serverResponse.(*handshake.MessageServerHello)
	var decision *negotiation.ConnectionID
	var srtpDecision negotiation.SRTPDecision
	if hasServerHello { //nolint:nestif
		if !serverHelloMsg.Version.Equal(protocol.Version1_2) {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
				dtlserrors.ErrUnsupportedProtocolVersion
		}
		offer := state.LocalClientHelloSnapshots.Current()
		if validationErr := negotiation.ValidateServerHello12Context(serverHelloMsg); validationErr != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, validationErr
		}
		if validationErr := negotiation.ValidateServerHelloResponse(offer, serverHelloMsg); validationErr != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.UnsupportedExtension}, validationErr
		}
		if srtpDecision, err = negotiation.ValidateSRTPSelection(
			offer,
			serverHelloMsg.Extensions,
			cfg.LocalSRTPProtectionProfiles,
		); err != nil {
			return 0, nil, err
		}
		decision = negotiation.DecideConnectionID(offer, serverHelloMsg.Extensions)
		if decision == nil {
			state.CommitNegotiatedExtensions(nil)
		}
		defer func() {
			if err != nil || dtlsAlert != nil {
				state.ResetConnectionIDs()
			}
		}()

		for _, v := range serverHelloMsg.Extensions {
			switch ext := v.(type) {
			case *extension12.ExtendedMasterSecret:
				if cfg.ExtendedMasterSecret != dtlsconfig.DisableExtendedMasterSecret {
					state.ExtendedMasterSecret = true
				}
			case *extension.ALPNSelection:
				state.NegotiatedProtocol = ext.Protocol
			}
		}

		if cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret && !state.ExtendedMasterSecret {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrClientRequiredButNoServerEMS //nolint:lll
		}

		remoteCipherSuite := ciphersuite.ForID(ciphersuite.ID(*serverHelloMsg.CipherSuiteID), cfg.CustomCipherSuites)
		if remoteCipherSuite == nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrCipherSuiteNoIntersection //nolint:lll
		}
		if !ciphersuite.IDSupportsVersion(remoteCipherSuite.ID(), protocol.Version1_2) {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrInvalidCipherSuite
		}

		selectedCipherSuite, found := dtlsflight.FindMatchingCipherSuite(
			[]dtlsconfig.CipherSuite{remoteCipherSuite}, cfg.LocalCipherSuites,
		)
		if !found {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrInvalidCipherSuite
		}

		state.CipherSuite = selectedCipherSuite
		state.RemoteRandom = serverHelloMsg.Random
		cfg.Log.Tracef("[handshake] use cipher suite: %s", selectedCipherSuite.String())

		if len(serverHelloMsg.SessionID) > 0 && bytes.Equal(state.SessionID, serverHelloMsg.SessionID) {
			next, dtlsAlert, err := handleResumption(ctx, conn, state, cache, cfg)
			if next != 0 && err == nil {
				state.CommitNegotiatedExtensions(decision)
				dtlsflight.CommitSRTP(state.Common, srtpDecision)
			}

			return next, dtlsAlert, err
		}

		if cfg.HasSessionStore && len(state.SessionID) > 0 {
			cfg.Log.Tracef("[handshake] clean old session : %s", state.SessionID)
			if err := cfg.DelSession(state.SessionID); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
		}

		if !cfg.HasSessionStore {
			state.SessionID = []byte{}
		} else {
			state.SessionID = bytes.Clone(serverHelloMsg.SessionID)
		}

		state.MasterSecret = []byte{}
	}

	var serverFlightPull dtlsflight.HandshakeCachePullResult
	if cfg.LocalPSKCallback != nil {
		serverFlightPull = cache.FullPullMapItems(state.HandshakeRecvSequence+1, state.CipherSuite,
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerKeyExchange, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true}, //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHelloDone, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},  //nolint:lll
		)
	} else {
		serverFlightPull = cache.FullPullMapItems(state.HandshakeRecvSequence+1, state.CipherSuite,
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificate, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true},        //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerKeyExchange, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false}, //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificateRequest, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true}, //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHelloDone, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},   //nolint:lll
		)
	}
	if serverFlightPull.Err != nil {
		return 0, nil, serverFlightPull.Err
	}
	if !serverFlightPull.Ready {
		// Don't have enough messages. Keep reading
		return 0, nil, nil
	}
	state.HandshakeRecvSequence = serverFlightPull.NextSequence

	if h, ok := serverFlightPull.Messages[handshake.TypeCertificate].(*handshake.MessageCertificate); ok {
		state.PeerCertificates = util.CloneByteSlices(h.Certificate)
	} else if state.CipherSuite.AuthenticationType() == ciphersuite.AuthenticationTypeCertificate {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, dtlserrors.ErrInvalidCertificate
	}

	if h, ok := serverFlightPull.Messages[handshake.TypeServerKeyExchange].(*handshake.MessageServerKeyExchange); ok {
		state.SetRemoteServerKeyExchange(h)
		alertPtr, err := handleServerKeyExchange(conn, state, cfg, h)
		if err != nil {
			return 0, alertPtr, err
		}
	} else {
		state.SetRemoteServerKeyExchange(nil)
	}

	if creq, ok := serverFlightPull.Messages[handshake.TypeCertificateRequest].(*handshake.MessageCertificateRequest); ok {
		state.RemoteCertRequestAlgs = slices.Clone(creq.SignatureHashAlgorithms)
		state.RemoteRequestedCertificate = true
	}
	state.CommitNegotiatedExtensions(decision)
	dtlsflight.CommitSRTP(state.Common, srtpDecision)

	return Flight5, nil, nil
}

func handleResumption(
	ctx context.Context,
	c dtlsflight.Conn,
	state *dtlsstate.State12,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (Flight, *alert.Alert, error) {
	if err := state.InitCipherSuite(); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	// Now, encrypted packets can be handled
	if err := c.HandleQueuedPackets(ctx); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	pull := cache.FullPullMapItems(state.HandshakeRecvSequence+1, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeFinished, Epoch: cfg.InitialEpoch + 1, IsClient: false, Optional: false}, //nolint:lll
	)
	if pull.Err != nil {
		return 0, nil, pull.Err
	}
	if !pull.Ready {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	finished, ok := pull.Messages[handshake.TypeFinished].(*handshake.MessageFinished)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}
	plainText := cache.PullAndMerge(
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},  //nolint:lll
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false}, //nolint:lll
	)

	expectedVerifyData, err := prf.VerifyDataServer(state.MasterSecret, plainText, state.CipherSuite.HashFunc())
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if !bytes.Equal(expectedVerifyData, finished.VerifyData) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrVerifyDataMismatch
	}

	clientRandom := state.LocalRandom.MarshalFixed()
	cfg.WriteKeyLog(keyLogLabel, clientRandom[:], state.MasterSecret)

	return Flight5b, nil, nil
}

//nolint:cyclop
func handleServerKeyExchange(
	_ dtlsflight.Conn,
	state *dtlsstate.State12,
	cfg *dtlsconfig.HandshakeConfig,
	keyExchangeMessage *handshake.MessageServerKeyExchange,
) (*alert.Alert, error) {
	var err error
	if state.CipherSuite == nil {
		return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrInvalidCipherSuite
	}
	if keyExchangeMessage.NamedCurve == elliptic.X25519MLKEM768 {
		return &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
			dtlserrors.ErrUnsupportedEllipticCurveVersion
	}

	if cfg.LocalPSKCallback != nil { //nolint:nestif
		var psk []byte
		if psk, err = cfg.LocalPSKCallback(bytes.Clone(keyExchangeMessage.IdentityHint)); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		state.IdentityHint = bytes.Clone(keyExchangeMessage.IdentityHint)
		switch state.CipherSuite.KeyExchangeAlgorithm() {
		case ciphersuite.KeyExchangeAlgorithmPsk:
			state.PreMasterSecret = prf.PSKPreMasterSecret(psk)
		case (ciphersuite.KeyExchangeAlgorithmEcdhe | ciphersuite.KeyExchangeAlgorithmPsk):
			if state.LocalKeypair, err = elliptic.GenerateKeypair(keyExchangeMessage.NamedCurve); err != nil {
				return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
			state.PreMasterSecret, err = prf.EcdhePSKPreMasterSecret(
				psk,
				keyExchangeMessage.PublicKey,
				state.LocalKeypair.PrivateKey,
				state.LocalKeypair.Curve,
			)
			if err != nil {
				return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
		default:
			return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrInvalidCipherSuite
		}
	} else {
		if state.LocalKeypair, err = elliptic.GenerateKeypair(keyExchangeMessage.NamedCurve); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}

		if state.PreMasterSecret, err = prf.PreMasterSecret(
			keyExchangeMessage.PublicKey,
			state.LocalKeypair.PrivateKey,
			state.LocalKeypair.Curve,
		); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	return nil, nil //nolint:nilnil
}

//nolint:cyclop
func flight3Generate(
	_ dtlsflight.Conn,
	state *dtlsstate.State12,
	_ *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	var extensions []extension.Value
	if len(cfg.LocalSignatureSchemes) > 0 {
		extensions = append(extensions, &extension.SignatureAlgorithms{
			Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes),
		})
	}
	extensions = append(extensions, &extension12.RenegotiationInfo{RenegotiatedConnection: 0})

	if len(cfg.LocalCertSignatureSchemes) > 0 {
		extensions = append(extensions, &extension.CertificateSignatureAlgorithms{
			Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalCertSignatureSchemes),
		})
	}

	if state.NamedCurve == 0 {
		if curves := supportedEllipticCurves(cfg.EllipticCurves); len(curves) > 0 {
			state.NamedCurve = curves[0]
		}
	}

	if state.NamedCurve != 0 {
		ellipticCurves := supportedEllipticCurves(cfg.EllipticCurves)

		extensions = append(extensions, []extension.Value{
			&extension.SupportedGroups{
				Groups: ellipticCurves,
			},
			&extension12.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}...)
	}

	if len(cfg.LocalSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &extension.SRTPOffer{
			ProtectionProfiles:  cfg.LocalSRTPProtectionProfiles,
			MasterKeyIdentifier: cfg.LocalSRTPMasterKeyIdentifier,
		})
	}

	if isExtendedMasterSecretRequested(cfg.ExtendedMasterSecret) {
		extensions = append(extensions, &extension12.ExtendedMasterSecret{})
	}

	if len(cfg.ServerName) > 0 {
		extensions = append(extensions, &extension.ServerNameOffer{ServerName: cfg.ServerName})
	}

	if len(cfg.SupportedProtocols) > 0 {
		extensions = append(extensions, &extension.ALPNOffer{Protocols: cfg.SupportedProtocols})
	}

	// If the generated first ClientHello offered a connection ID, use the
	// exact post-hook value as the default in the second ClientHello.
	cid, cidOffered := negotiation.ConnectionIDOffer(state.LocalClientHelloSnapshots.Initial())
	if cfg.ConnectionIDGenerator != nil && cidOffered {
		extensions = dtlsflight.AppendConnectionIDExtensions(
			extensions,
			cid,
			cfg.EnableRRC && state.LocalClientHelloSnapshots.Initial().Offered(extension.TypeReturnRoutabilityCheck),
		)
	}

	clientHello := &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		SessionID:          state.SessionID,
		Cookie:             state.Cookie,
		Random:             state.LocalRandom,
		CipherSuiteIDs:     dtlsflight.CipherSuiteIDs(cfg.LocalCipherSuites),
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
	}
	clientHello.Extensions = extensions
	if state.HasHelloVerifyRequest {
		retry, err := negotiation.ClientHelloFromSnapshot(
			state.LocalClientHelloSnapshots.Initial(),
		)
		if err != nil {
			return nil, nil, err
		}
		retry.Cookie = state.Cookie
		clientHello = retry
	}

	clientHello, snapshot, err := dtlsflight.FinalizeClientHello(
		clientHello, cfg.ClientHelloMessageHook, cfg.EnableRRC,
	)
	if err != nil {
		return nil, nil, err
	}
	if state.HasHelloVerifyRequest {
		if err := negotiation.ValidateHelloVerifyRequestResponse(
			state.LocalClientHelloSnapshots.Initial(), snapshot, state.Cookie,
		); err != nil {
			return nil, nil, err
		}
	}
	if err := state.RecordLocalClientHello(snapshot); err != nil {
		return nil, nil, err
	}
	content := handshake.Handshake{Message: clientHello}

	return []*dtlsflight.Outbound{
		{
			Content: &content,
		},
	}, nil, nil
}

func isExtendedMasterSecretRequested(policy dtlsconfig.ExtendedMasterSecretType) bool {
	return policy == dtlsconfig.RequestExtendedMasterSecret ||
		policy == dtlsconfig.RequireExtendedMasterSecret
}
