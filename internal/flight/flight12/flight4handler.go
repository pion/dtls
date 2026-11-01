// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"slices"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	dtlscrypto "github.com/pion/dtls/v4/internal/handshakecrypto"
	"github.com/pion/dtls/v4/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/internal/util"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/crypto/prf"
	"github.com/pion/dtls/v4/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls12"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	handshake12 "github.com/pion/dtls/v4/pkg/protocol/handshake/dtls12"
)

func flight4Parse(ctx context.Context, conn dtlsflight.Conn, state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) (Flight, *alert.Alert, error) {
	if !state.ClientFlightProcessed {
		ready, dtlsAlert, err := flight4ProcessClientFlight(state, cache, cfg)
		if !ready || err != nil {
			return 0, dtlsAlert, err
		}
	}

	// Now, encrypted packets can be handled
	if err := conn.HandleQueuedPackets(ctx); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	finishedPull := cache.FullPullMapItems(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeFinished, Epoch: cfg.InitialEpoch + 1, IsClient: true, Optional: false},
	)
	if finishedPull.Err != nil {
		return 0, nil, finishedPull.Err
	}
	if !finishedPull.Ready {
		// No valid message received. Keep reading
		return 0, nil, nil
	}
	finished, ok := finishedPull.Messages[handshake.TypeFinished].(*handshake.MessageFinished)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	transcript := cache.PullAndMerge(append(handshakeRulesThroughClientKeyExchange(cfg.InitialEpoch),
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificateVerify, Epoch: cfg.InitialEpoch, IsClient: true},
	)...)
	expected, err := prf.VerifyDataClient(state.MasterSecret, transcript, state.CipherSuite.HashFunc())
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if subtle.ConstantTimeCompare(expected, finished.VerifyData) != 1 {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrVerifyDataMismatch
	}
	state.HandshakeRecvSequence = finishedPull.NextSequence

	return finishVerifiedClientFlight(state, cfg)
}

func finishVerifiedClientFlight(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig) (Flight, *alert.Alert, error) {
	// empty certificate list is valid for PSK suites.
	// https://www.rfc-editor.org/rfc/rfc4279.html#section-2
	// https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.6
	if state.CipherSuite.AuthenticationType() == cryptosuite.AuthenticationTypeCertificate {
		if dtlsAlert, err := validateClientAuth(state, cfg); err != nil {
			return 0, dtlsAlert, err
		}
	}
	if cfg.VerifyConnection != nil {
		if err := cfg.VerifyConnection(state); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
		}
	}

	return finishClientFlight(state, cfg)
}

func validateClientAuth(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig) (*alert.Alert, error) {
	if (cfg.ClientAuth == dtlsconfig.RequireAnyClientCert || cfg.ClientAuth == dtlsconfig.RequireAndVerifyClientCert) && len(state.PeerCertificates) == 0 {
		return &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, dtlserrors.ErrClientCertificateRequired
	}
	if (cfg.ClientAuth == dtlsconfig.VerifyClientCertIfGiven || cfg.ClientAuth == dtlsconfig.RequireAndVerifyClientCert) && len(state.PeerCertificates) > 0 && !state.PeerCertificatesVerified {
		return &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, dtlserrors.ErrClientCertificateNotVerified
	}

	return nil, nil //nolint:nilnil
}

// Retain progress while waiting for CertificateVerify and Finished.
func flight4ProcessClientFlight(state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) (bool, *alert.Alert, error) {
	if state.ClientKeyExchange == nil {
		if ready, dtlsAlert, err := processClientKeyExchange(state, cache, cfg); !ready || err != nil {
			return ready, dtlsAlert, err
		}
	}
	clientKeyExchange := state.ClientKeyExchange
	pull := cache.FullPullMapItems(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificateVerify, Epoch: cfg.InitialEpoch, IsClient: true, Optional: true},
	)
	if pull.Err != nil {
		return false, nil, pull.Err
	}
	//nolint:nestif
	if verify, hasVerify := pull.Messages[handshake.TypeCertificateVerify].(*handshake.MessageCertificateVerify); hasVerify {
		if _, dtlsAlert, err := verifyClientCertificateMessage(state, cache, cfg, verify); err != nil {
			return false, dtlsAlert, err
		}
	} else if len(state.PeerCertificates) > 0 {
		// A certificate was received, but we haven't seen a CertificateVerify
		// keep reading until we receive one
		return false, nil, nil
	}

	if state.Protection == nil {
		if _, dtlsAlert, err := initializeServerCipherSuite(state, cache, cfg, clientKeyExchange); err != nil {
			return false, dtlsAlert, err
		}
	}

	state.HandshakeRecvSequence = pull.NextSequence
	state.ClientKeyExchange = nil
	state.ClientFlightProcessed = true

	return true, nil, nil
}

func processClientKeyExchange(state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) (bool, *alert.Alert, error) {
	pull := cache.FullPullMapItems(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificate, Epoch: cfg.InitialEpoch, IsClient: true, Optional: true},
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientKeyExchange, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},
	)
	if pull.Err != nil {
		return false, nil, pull.Err
	}
	if !pull.Ready {
		// No valid message received. Keep reading
		return false, nil, nil
	}

	// Validate type
	clientKeyExchange, ok := pull.Messages[handshake.TypeClientKeyExchange].(*handshake.MessageClientKeyExchange)
	if !ok {
		return false, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if h, hasCert := pull.Messages[handshake.TypeCertificate].(*handshake12.MessageCertificate); hasCert {
		if cfg.ClientAuth == dtlsconfig.NoClientCert {
			return false, &alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage}, dtlserrors.ErrInvalidCertificate
		}
		state.PeerCertificates = util.CloneByteSlices(h.Certificate)
		// If the client offer its certificate, just disable session resumption.
		// Otherwise, we have to store the certificate identitfication and expire time.
		// And we have to check whether this certificate expired, revoked or changed.
		//
		// https://curl.se/docs/CVE-2016-5419.html
		state.SessionID = nil
	}

	state.ClientKeyExchange = clientKeyExchange
	state.HandshakeRecvSequence = pull.NextSequence

	return true, nil, nil
}

func verifyClientCertificateMessage(state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig, verify *handshake.MessageCertificateVerify) (bool, *alert.Alert, error) {
	if len(state.PeerCertificates) == 0 {
		return false, &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, dtlserrors.ErrCertificateVerifyNoCertificate
	}

	plainText := cache.PullAndMerge(handshakeRulesThroughClientKeyExchange(cfg.InitialEpoch)...)

	// Verify that the pair of hash algorithm and signiture is listed.
	if !slices.Contains(cfg.LocalSignatureSchemes, signaturehash.Algorithm{Hash: verify.HashAlgorithm, Signature: verify.SignatureAlgorithm}) {
		return false, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrNoAvailableSignatureSchemes
	}

	if err := dtlscrypto.VerifyCertificateVerify(plainText, verify.HashAlgorithm, verify.SignatureAlgorithm, verify.Signature, state.PeerCertificates, protocol.Version1_2); err != nil {
		return false, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
	}

	var chains [][]*x509.Certificate
	var err error
	var verified bool
	if cfg.ClientAuth >= dtlsconfig.VerifyClientCertIfGiven {
		// Use cert-specific algorithms if present, otherwise fall back to signature_algorithms per RFC 8446
		certAlgs := cfg.LocalCertSignatureSchemes
		if len(certAlgs) == 0 {
			certAlgs = cfg.LocalSignatureSchemes
		}
		if chains, err = dtlscrypto.VerifyClientCert(state.PeerCertificates, cfg.ClientCAs, certAlgs); err != nil {
			return false, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
		}
		verified = true
	}
	if cfg.VerifyPeerCertificate != nil {
		if err := cfg.VerifyPeerCertificate(state.PeerCertificates, chains); err != nil {
			return false, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
		}
	}
	state.PeerCertificatesVerified = verified

	return true, nil, nil
}

func initializeServerCipherSuite(state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig, clientKeyExchange *handshake.MessageClientKeyExchange) (bool, *alert.Alert, error) {
	serverRandom := state.LocalRandom.MarshalFixed()
	clientRandom := state.RemoteRandom.MarshalFixed()

	preMasterSecret, dtlsAlert, err := clientPreMasterSecret(state, cfg, clientKeyExchange)
	if err != nil {
		return false, dtlsAlert, err
	}

	if state.ExtendedMasterSecret {
		var sessionHash []byte
		sessionHash, err = cache.SessionHash(state.CipherSuite.HashFunc(), cfg.InitialEpoch)
		if err != nil {
			return false, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}

		state.MasterSecret, err = prf.ExtendedMasterSecret(preMasterSecret, sessionHash, state.CipherSuite.HashFunc())
	} else {
		state.MasterSecret, err = prf.MasterSecret(preMasterSecret, clientRandom[:], serverRandom[:], state.CipherSuite.HashFunc())
	}
	if err != nil {
		return false, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	if err := state.InitCipherSuite(); err != nil {
		return false, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	cfg.WriteKeyLog(keyLogLabel, clientRandom[:], state.MasterSecret)

	return true, nil, nil
}

func clientPreMasterSecret(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, clientKeyExchange *handshake.MessageClientKeyExchange) ([]byte, *alert.Alert, error) {
	if state.CipherSuite.AuthenticationType() != cryptosuite.AuthenticationTypePreSharedKey {
		secret, err := prf.PreMasterSecret(clientKeyExchange.PublicKey, state.LocalKeypair.PrivateKey, state.LocalKeypair.Curve)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
		}

		return secret, nil, nil
	}
	_, psk, _, err := cfg.SelectPSK([][]byte{clientKeyExchange.IdentityHint})
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if len(psk) == 0 {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrPSKNotNegotiated
	}
	state.IdentityHint = bytes.Clone(clientKeyExchange.IdentityHint)
	state.PSKHash = sha256.Sum256(psk)

	var secret []byte
	switch state.CipherSuite.KeyExchangeAlgorithm() {
	case cryptosuite.KeyExchangeAlgorithmPsk:
		return prf.PSKPreMasterSecret(psk), nil, nil
	case cryptosuite.KeyExchangeAlgorithmPsk | cryptosuite.KeyExchangeAlgorithmEcdhe:
		secret, err = prf.EcdhePSKPreMasterSecret(psk, clientKeyExchange.PublicKey, state.LocalKeypair.PrivateKey, state.LocalKeypair.Curve)
	default:
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, dtlserrors.ErrInvalidCipherSuite
	}
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	return secret, nil, nil
}

func flight4Generate(_ dtlsflight.Conn, state *dtlsstate.State12, _ *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	offer := state.RemoteClientHelloSnapshots.Current()
	srtpSelection, err := negotiation.NegotiateSRTP(offer, cfg.LocalSRTPProtectionProfiles, cfg.LocalSRTPMasterKeyIdentifier)
	if err != nil {
		return nil, nil, err
	}

	serverHello, alertMsg, err := generateServerHello(state, cfg, offer, srtpSelection)
	if err != nil {
		return nil, alertMsg, err
	}
	var pkts []*dtlsflight.Outbound
	decision := negotiation.DecideConnectionID(offer, serverHello.Extensions)
	content := handshake.Handshake{Message: serverHello}

	pkts = append(pkts, &dtlsflight.Outbound{
		Content: &content,
	})

	switch {
	case state.CipherSuite.AuthenticationType() == cryptosuite.AuthenticationTypeCertificate:
		certificatePackets, alertMsg, err := serverCertificateFlight(state, cfg)
		if err != nil {
			return nil, alertMsg, err
		}
		pkts = append(pkts, certificatePackets...)
	case cfg.LocalPSKIdentityHint != nil ||
		state.CipherSuite.KeyExchangeAlgorithm().Has(cryptosuite.KeyExchangeAlgorithmEcdhe):
		// To help the client in selecting which identity to use, the server
		// can provide a "PSK identity hint" in the ServerKeyExchange message.
		// If no hint is provided and cipher suite doesn't use elliptic curve,
		// the ServerKeyExchange message is omitted.
		//
		// https://tools.ietf.org/html/rfc4279#section-2
		srvExchange := unsignedServerKeyExchange(state, cfg.LocalPSKIdentityHint)
		pkts = append(pkts, &dtlsflight.Outbound{
			Content: &handshake.Handshake{
				Message: srvExchange,
			},
		})
	}

	pkts = append(pkts, &dtlsflight.Outbound{
		Content: &handshake.Handshake{
			Message: &handshake.MessageServerHelloDone{},
		},
	})
	state.CommitNegotiatedExtensions(decision)
	dtlsflight.CommitSRTP(state.Common, srtpSelection)

	return pkts, nil, nil
}

func serverHelloBaseExtensions(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, offer negotiation.ClientHelloSnapshot, srtpSelection negotiation.SRTPDecision) []extension.Value {
	extensions := []extension.Value{}
	if (cfg.ExtendedMasterSecret == dtlsconfig.RequestExtendedMasterSecret || cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret) && state.ExtendedMasterSecret {
		extensions = append(extensions, &extension12.ExtendedMasterSecret{})
	}
	extensions = appendSRTPSelection(extensions, srtpSelection)
	if state.RemoteSupportsRenegotiation {
		extensions = append(extensions, &extension12.RenegotiationInfo{
			RenegotiatedConnection: 0,
		})
	}
	if state.CipherSuite.AuthenticationType() == cryptosuite.AuthenticationTypeCertificate && offer.Offered(extension.TypeSupportedPointFormats) {
		extensions = append(extensions, &extension12.SupportedPointFormats{PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed}})
	}

	return extensions
}

func serverHelloExtensions(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, offer negotiation.ClientHelloSnapshot, srtpSelection negotiation.SRTPDecision) ([]extension.Value, *alert.Alert, error) {
	extensions := serverHelloBaseExtensions(state, cfg, offer, srtpSelection)
	selectedProto, err := extension.ALPNProtocolSelection(cfg.SupportedProtocols, state.PeerSupportedProtocols)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.NoApplicationProtocol}, err
	}
	if selectedProto != "" {
		extensions = append(extensions, &extension.ALPNSelection{Protocol: selectedProto})
		state.NegotiatedProtocol = selectedProto
	}

	cid, err := serverCIDExtension(state, cfg, offer)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if cid != nil {
		extensions = dtlsflight.AppendConnectionIDExtensions(extensions, cid.CID, cfg.EnableRRC && offer.Offered(extension.TypeReturnRoutabilityCheck))
	}

	return extensions, nil, nil
}

func generateServerHello(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, offer negotiation.ClientHelloSnapshot, srtpSelection negotiation.SRTPDecision) (*handshake.MessageServerHello, *alert.Alert, error) {
	extensions, alertMsg, err := serverHelloExtensions(state, cfg, offer, srtpSelection)
	if err != nil {
		return nil, alertMsg, err
	}

	cipherSuiteID := uint16(state.CipherSuite.ID())

	if cfg.HasSessionStore {
		state.SessionID = make([]byte, sessionLength)
		if _, err = rand.Read(state.SessionID); err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	serverHello := &handshake.MessageServerHello{Version: protocol.Version1_2, Random: state.LocalRandom, SessionID: state.SessionID, CipherSuiteID: &cipherSuiteID, CompressionMethod: dtlsflight.DefaultCompressionMethods()[0], Extensions: extensions}

	serverHello, err = dtlsflight.FinalizeServerHello(
		serverHello, cfg.ServerHelloMessageHook, offer, cfg.EnableRRC,
	)
	if err != nil {
		return nil, nil, err
	}
	if err = dtlsflight.ValidateHookedConnectionIDLength(serverHello.Extensions, cfg, cfg.ServerHelloMessageHook != nil); err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if err = validateServerSRTP(offer, serverHello.Extensions, cfg.LocalSRTPProtectionProfiles, srtpSelection); err != nil {
		return nil, nil, err
	}

	return serverHello, nil, nil
}

func serverCertificateFlight(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	var pkts []*dtlsflight.Outbound
	certificate := state.ServerCertificate
	var err error
	if certificate == nil {
		certificate, err = cfg.GetCertificate(&dtlsconfig.ClientHelloInfo{ServerName: state.ServerName, CipherSuites: []cryptosuite.ID{state.CipherSuite.ID()}, RandomBytes: state.RemoteRandom.RandomBytes})
	}
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
	}

	pkts = append(pkts, &dtlsflight.Outbound{Content: &handshake.Handshake{Message: &handshake12.MessageCertificate{Certificate: certificate.Certificate}}})

	serverRandom := state.LocalRandom.MarshalFixed()
	clientRandom := state.RemoteRandom.MarshalFixed()

	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, dtlserrors.ErrInvalidPrivateKey
	}

	// Find compatible signature scheme
	signatureHashAlgo, err := signaturehash.SelectSignatureScheme(
		cfg.LocalSignatureSchemes,
		signer,
		protocol.Version1_2,
	)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, err
	}

	signature, err := dtlscrypto.GenerateKeySignature(clientRandom[:], serverRandom[:], state.LocalKeypair.PublicKey, state.NamedCurve, signer, signatureHashAlgo.Hash, signatureHashAlgo.Signature)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	state.LocalKeySignature = signature

	pkts = append(pkts, &dtlsflight.Outbound{
		Content: &handshake.Handshake{
			Message: &handshake.MessageServerKeyExchange{EllipticCurveType: elliptic.CurveTypeNamedCurve, NamedCurve: state.NamedCurve, PublicKey: state.LocalKeypair.PublicKey, HashAlgorithm: signatureHashAlgo.Hash, SignatureAlgorithm: signatureHashAlgo.Signature, Signature: state.LocalKeySignature},
		},
	})

	if cfg.ClientAuth > dtlsconfig.NoClientCert {
		// An empty list of certificateAuthorities signals to
		// the client that it may send any certificate in response
		// to our request. When we know the CAs we trust, then
		// we can send them down, so that the client can choose
		// an appropriate certificate to give to us.
		var certificateAuthorities [][]byte
		if cfg.ClientCAs != nil {
			// nolint:staticcheck // ignoring tlsCert.RootCAs.Subjects is deprecated ERR
			// because cert does not come from SystemCertPool and it's ok if certificate
			// authorities is empty.
			certificateAuthorities = cfg.ClientCAs.Subjects()
		}

		certReq := &handshake12.MessageCertificateRequest{CertificateTypes: []clientcertificate.Type{clientcertificate.RSASign, clientcertificate.ECDSASign}, SignatureHashAlgorithms: cfg.LocalSignatureSchemes, CertificateAuthoritiesNames: certificateAuthorities}

		var content handshake.Handshake

		if cfg.CertificateRequestMessageHook != nil {
			content = handshake.Handshake{Message: cfg.CertificateRequestMessageHook(*certReq)}
		} else {
			content = handshake.Handshake{Message: certReq}
		}

		pkts = append(pkts, &dtlsflight.Outbound{
			Content: &content,
		})
	}

	return pkts, nil, nil
}

func unsignedServerKeyExchange(state *dtlsstate.State12, identityHint []byte) *handshake.MessageServerKeyExchange {
	srvExchange := &handshake.MessageServerKeyExchange{
		IdentityHint: identityHint,
	}
	if state.CipherSuite.KeyExchangeAlgorithm().Has(cryptosuite.KeyExchangeAlgorithmEcdhe) {
		// ECDHE-PSK always encodes the hint length, including an empty hint.
		// ServerKeyExchange is always sent, even when the hint is empty.
		// https://www.rfc-editor.org/rfc/rfc5489.html#section-2
		if state.CipherSuite.AuthenticationType() == cryptosuite.AuthenticationTypePreSharedKey &&
			srvExchange.IdentityHint == nil {
			srvExchange.IdentityHint = []byte{}
		}
		srvExchange.EllipticCurveType = elliptic.CurveTypeNamedCurve
		srvExchange.NamedCurve = state.NamedCurve
		srvExchange.PublicKey = state.LocalKeypair.PublicKey
	}

	return srvExchange
}

func serverCIDExtension(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, offer negotiation.ClientHelloSnapshot) (*extension.ConnectionID, error) {
	if cfg.ConnectionIDGenerator == nil || !offer.Offered(extension.TypeConnectionID) {
		return nil, nil //nolint:nilnil // No extension is a successful outcome.
	}
	cid := state.LocalConnectionID()
	if !state.LocalCIDOffered {
		var err error
		cid, err = cfg.GenerateConnectionID()
		if err != nil {
			return nil, err
		}
	}

	return &extension.ConnectionID{CID: cid}, nil
}

func finishClientFlight(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig) (Flight, *alert.Alert, error) {
	if len(state.SessionID) > 0 && cfg.HasSessionStore {
		cfg.Log.Tracef("[handshake] save new session: %x", state.SessionID)
		if err := cfg.SetSession(state.SessionID, state.Session()); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	return Flight6, nil, nil
}
