// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"slices"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/internal/util"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/crypto/prf"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls12"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

func flight3Parse(ctx context.Context, conn dtlsflight.Conn, state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) (next Flight, dtlsAlert *alert.Alert, err error) {
	// Clients may receive multiple HelloVerifyRequest messages with different cookies.
	// Clients SHOULD handle this by sending a new ClientHello with a cookie in response
	// to the new HelloVerifyRequest. RFC 6347 Section 4.2.1
	serverResponsePull := cache.FullPullMapOneOfItems(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeHelloVerifyRequest, Epoch: cfg.InitialEpoch, IsClient: false},
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false},
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
		if h.Version != protocol.Version1_0 && h.Version != protocol.Version1_2 {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlserrors.ErrUnsupportedProtocolVersion
		}
		state.Cookie = bytes.Clone(h.Cookie)
		state.HasHelloVerifyRequest = true
		state.HandshakeRecvSequence = serverResponsePull.NextSequence

		return Flight3, nil, nil
	}

	return parseServerHelloFlight(ctx, conn, state, cache, cfg, serverResponsePull)
}

func parseServerHelloFlight(ctx context.Context, conn dtlsflight.Conn, state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig, serverResponsePull dtlsflight.HandshakeCachePullResult) (next Flight, dtlsAlert *alert.Alert, err error) {
	serverResponse := serverResponsePull.Messages[handshake.TypeServerHello]
	serverHelloMsg, hasServerHello := serverResponse.(*handshake.MessageServerHello)
	var decision *negotiation.ConnectionID
	var srtpDecision negotiation.SRTPDecision
	if hasServerHello { //nolint:nestif
		offer := state.LocalClientHelloSnapshots.Current()
		if validationAlert, validationErr := validateServerHello12Version(serverHelloMsg, cfg, offer); validationErr != nil {
			return 0, validationAlert, validationErr
		}
		if srtpDecision, err = negotiation.ValidateSRTPSelection(offer, serverHelloMsg.Extensions, cfg.LocalSRTPProtectionProfiles); err != nil {
			return 0, nil, err
		}
		decision = negotiation.DecideConnectionID(offer, serverHelloMsg.Extensions)
		if decision == nil {
			state.CommitNegotiatedExtensions(nil)
		}
		defer func() {
			resetConnectionIDsOnFailure(state, dtlsAlert, err)
		}()

		if dtlsAlert, err := processServerHello12Extensions(state, cfg, serverHelloMsg, offer); err != nil {
			return 0, dtlsAlert, err
		}

		selectedCipherSuite, found := dtlsflight.FindCipherSuiteByID(
			*serverHelloMsg.CipherSuiteID,
			cfg.LocalCipherSuites,
		)
		if !found {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrCipherSuiteNoIntersection
		}
		if !selectedCipherSuite.Capabilities().SupportsVersion(protocol.Version1_2) {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrInvalidCipherSuite
		}

		state.CipherSuite = selectedCipherSuite
		state.RemoteRandom = serverHelloMsg.Random
		cfg.Log.Tracef("[handshake] use cipher suite: %s", selectedCipherSuite.String())

		if serverAcceptedSession(state, serverHelloMsg) {
			return resumeClientSession(ctx, conn, state, cache, cfg, decision, srtpDecision)
		}

		if dtlsAlert, err := resetClientSession(conn, state, cfg, serverHelloMsg); err != nil {
			return 0, dtlsAlert, err
		}
	}

	return parseServerKeyFlight(conn, state, cache, cfg, decision, srtpDecision)
}

func parseServerKeyFlight(conn dtlsflight.Conn, state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig, decision *negotiation.ConnectionID, srtpDecision negotiation.SRTPDecision) (Flight, *alert.Alert, error) {
	var serverFlightPull dtlsflight.HandshakeCachePullResult
	if cfg.LocalPSKCallback != nil {
		serverFlightPull = cache.FullPullMapItems(state.HandshakeRecvSequence+1, state.CipherSuite,
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerKeyExchange, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true},
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHelloDone, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},
		)
	} else {
		serverFlightPull = cache.FullPullMapItems(state.HandshakeRecvSequence+1, state.CipherSuite,
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificate, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true},
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerKeyExchange, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificateRequest, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true},
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHelloDone, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},
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
	} else if state.CipherSuite.AuthenticationType() == cryptosuite.AuthenticationTypeCertificate {
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

func validateServerHello12Version(serverHelloMsg *handshake.MessageServerHello, cfg *dtlsconfig.HandshakeConfig, offer negotiation.ClientHelloSnapshot) (*alert.Alert, error) {
	if serverHelloMsg.Version != protocol.Version1_2 {
		return &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlserrors.ErrUnsupportedProtocolVersion
	}
	if cfg.MaxVersion == protocol.Version1_3 &&
		(bytes.HasSuffix(serverHelloMsg.Random.RandomBytes[:], []byte(downgradeSentinel12)) ||
			bytes.HasSuffix(serverHelloMsg.Random.RandomBytes[:], []byte(downgradeSentinel10))) {
		return &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, fmt.Errorf("downgrade sentinel in DTLS 1.2 ServerHello: %w", dtlserrors.ErrInvalidServerHello)
	}
	if validationErr := negotiation.ValidateServerHello12Context(serverHelloMsg); validationErr != nil {
		return &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, validationErr
	}
	if validationErr := negotiation.ValidateServerHelloResponse(offer, serverHelloMsg); validationErr != nil {
		return &alert.Alert{Level: alert.Fatal, Description: alert.UnsupportedExtension}, validationErr
	}

	return nil, nil //nolint:nilnil
}

func processServerHello12Extensions(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, serverHelloMsg *handshake.MessageServerHello, offer negotiation.ClientHelloSnapshot) (*alert.Alert, error) {
	state.NegotiatedProtocol = ""
	for _, v := range serverHelloMsg.Extensions {
		switch ext := v.(type) {
		case *extension12.ExtendedMasterSecret:
			if cfg.ExtendedMasterSecret != dtlsconfig.DisableExtendedMasterSecret {
				state.ExtendedMasterSecret = true
			}
		case *extension.ALPNSelection:
			raw, offered := offer.Extension(extension.TypeALPN)
			var protocols extension.ALPNOffer
			if !offered || protocols.UnmarshalData(raw.Data) != nil || !slices.Contains(protocols.Protocols, ext.Protocol) {
				return &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlserrors.ErrALPNNoAppProto
			}
			state.NegotiatedProtocol = ext.Protocol
		}
	}

	if cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret && !state.ExtendedMasterSecret {
		return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrClientRequiredButNoServerEMS
	}

	return nil, nil //nolint:nilnil
}

func serverAcceptedSession(state *dtlsstate.State12, serverHelloMsg *handshake.MessageServerHello) bool {
	return state.ResumeSession != nil && len(serverHelloMsg.SessionID) > 0 && bytes.Equal(state.ResumeSession.ID, serverHelloMsg.SessionID)
}

func resumeClientSession(ctx context.Context, conn dtlsflight.Conn, state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig, decision *negotiation.ConnectionID, srtpDecision negotiation.SRTPDecision) (Flight, *alert.Alert, error) {
	if state.ResumeSession.CipherSuiteID != state.CipherSuite.ID() {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlserrors.ErrInvalidCipherSuite
	}
	if state.ResumeSession.ExtendedMasterSecret != state.ExtendedMasterSecret {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrSessionEMSMismatch
	}
	next, dtlsAlert, err := handleResumption(ctx, conn, state, cache, cfg)
	if next != 0 && err == nil {
		state.CommitNegotiatedExtensions(decision)
		dtlsflight.CommitSRTP(state.Common, srtpDecision)
	}

	return next, dtlsAlert, err
}

func resetClientSession(conn dtlsflight.Conn, state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, serverHelloMsg *handshake.MessageServerHello) (*alert.Alert, error) {
	if cfg.HasSessionStore && state.ResumeSession != nil {
		cfg.Log.Tracef("[handshake] clean old session : %s", state.SessionID)
		if err := cfg.DelSession(conn.SessionKey()); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	if !cfg.HasSessionStore {
		state.SessionID = []byte{}
	} else {
		state.SessionID = bytes.Clone(serverHelloMsg.SessionID)
	}

	state.MasterSecret = []byte{}
	state.ResumeSession = nil
	state.PeerCertificates = nil
	state.IdentityHint = nil

	return nil, nil //nolint:nilnil
}

func resetConnectionIDsOnFailure(state *dtlsstate.State12, dtlsAlert *alert.Alert, err error) {
	if err != nil || dtlsAlert != nil {
		state.ResetConnectionIDs()
	}
}

func handleResumption(ctx context.Context, c dtlsflight.Conn, state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) (Flight, *alert.Alert, error) {
	if err := state.InitCipherSuite(); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	// Now, encrypted packets can be handled
	if err := c.HandleQueuedPackets(ctx); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	pull := cache.FullPullMapItems(state.HandshakeRecvSequence+1, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeFinished, Epoch: cfg.InitialEpoch + 1, IsClient: false, Optional: false},
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
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},
	)

	expectedVerifyData, err := prf.VerifyDataServer(state.MasterSecret, plainText, state.CipherSuite.HashFunc())
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if !bytes.Equal(expectedVerifyData, finished.VerifyData) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrVerifyDataMismatch
	}
	if err := cfg.VerifyResumedConnection(state); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
	}

	clientRandom := state.LocalRandom.MarshalFixed()
	cfg.WriteKeyLog(keyLogLabel, clientRandom[:], state.MasterSecret)

	return Flight5b, nil, nil
}

func handleServerKeyExchange(_ dtlsflight.Conn, state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, keyExchangeMessage *handshake.MessageServerKeyExchange) (*alert.Alert, error) {
	var err error
	if state.CipherSuite == nil {
		return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrInvalidCipherSuite
	}
	if keyExchangeMessage.NamedCurve == elliptic.X25519MLKEM768 {
		return &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlserrors.ErrUnsupportedEllipticCurveVersion
	}
	if state.CipherSuite.KeyExchangeAlgorithm().Has(cryptosuite.KeyExchangeAlgorithmEcdhe) {
		if err = validateServerSelectedCurve(state, keyExchangeMessage.NamedCurve); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
		}
	}

	if cfg.LocalPSKCallback != nil { //nolint:nestif
		return handlePSKServerKeyExchange(state, cfg, keyExchangeMessage)
	} else {
		if state.LocalKeypair, err = elliptic.GenerateKeypair(keyExchangeMessage.NamedCurve); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}

		if state.PreMasterSecret, err = prf.PreMasterSecret(keyExchangeMessage.PublicKey, state.LocalKeypair.PrivateKey, state.LocalKeypair.Curve); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	return nil, nil //nolint:nilnil
}

func handlePSKServerKeyExchange(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, keyExchangeMessage *handshake.MessageServerKeyExchange) (*alert.Alert, error) {
	var err error
	var psk []byte
	if psk, err = cfg.LocalPSKCallback(bytes.Clone(keyExchangeMessage.IdentityHint)); err != nil {
		return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	state.IdentityHint = bytes.Clone(keyExchangeMessage.IdentityHint)
	state.PSKHash = sha256.Sum256(psk)
	switch state.CipherSuite.KeyExchangeAlgorithm() {
	case cryptosuite.KeyExchangeAlgorithmPsk:
		state.PreMasterSecret = prf.PSKPreMasterSecret(psk)
	case (cryptosuite.KeyExchangeAlgorithmEcdhe | cryptosuite.KeyExchangeAlgorithmPsk):
		if state.LocalKeypair, err = elliptic.GenerateKeypair(keyExchangeMessage.NamedCurve); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		state.PreMasterSecret, err = prf.EcdhePSKPreMasterSecret(psk, keyExchangeMessage.PublicKey, state.LocalKeypair.PrivateKey, state.LocalKeypair.Curve)
		if err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	default:
		return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrInvalidCipherSuite
	}

	return nil, nil //nolint:nilnil
}

func flight3Generate(_ dtlsflight.Conn, state *dtlsstate.State12, _ *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	extensions := clientHello12SignatureExtensions(cfg)

	if state.NamedCurve == 0 {
		if curves := supportedEllipticCurves(cfg.EllipticCurves); len(curves) > 0 {
			state.NamedCurve = curves[0]
		}
	}

	if state.NamedCurve != 0 {
		ellipticCurves := supportedEllipticCurves(cfg.EllipticCurves)

		extensions = append(extensions, []extension.Value{&extension.SupportedGroups{Groups: ellipticCurves}, &extension12.SupportedPointFormats{PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed}}}...)
	}

	extensions = appendClientHello12Negotiation(extensions, cfg)

	return generateRetryClientHello(state, cfg, extensions)
}

func generateRetryClientHello(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, extensions []extension.Value) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	// If the generated first ClientHello offered a connection ID, use the
	// exact post-hook value as the default in the second ClientHello.
	cid, cidOffered := negotiation.ConnectionIDOffer(state.LocalClientHelloSnapshots.Initial())
	if cfg.ConnectionIDGenerator != nil && cidOffered {
		extensions = dtlsflight.AppendConnectionIDExtensions(extensions, cid, cfg.EnableRRC && state.LocalClientHelloSnapshots.Initial().Offered(extension.TypeReturnRoutabilityCheck))
	}

	clientHello := &handshake.MessageClientHello{Version: protocol.Version1_2, SessionID: state.SessionID, Cookie: state.Cookie, Random: state.LocalRandom, CipherSuiteIDs: dtlsflight.CipherSuiteIDs(cfg.LocalCipherSuites), CompressionMethods: dtlsflight.DefaultCompressionMethods(), Extensions: extensions}
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

	return finalizeClientHello12(state, cfg, clientHello, true)
}

func isExtendedMasterSecretRequested(policy dtlsconfig.ExtendedMasterSecretType) bool {
	return policy == dtlsconfig.RequestExtendedMasterSecret ||
		policy == dtlsconfig.RequireExtendedMasterSecret
}

func validateServerSelectedCurve(state *dtlsstate.State12, curve elliptic.Curve) error {
	hello, err := negotiation.ClientHelloFromSnapshot(state.LocalClientHelloSnapshots.Current())
	if err != nil {
		return err
	}
	for _, value := range hello.Extensions {
		if groups, ok := value.(*extension.SupportedGroups); ok && !slices.Contains(groups.Groups, curve) {
			return dtlserrors.ErrServerSelectedUnofferedCurve
		}
	}

	return nil
}
