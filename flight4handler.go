// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

//nolint:gocognit,gocyclo,lll,cyclop,maintidx
func flight4Parse(
	ctx context.Context,
	conn flightConn,
	state *dtlsstate.State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *alert.Alert, error) {
	seq, msgs, ok := cache.fullPullMap(state.HandshakeRecvSequence, state.CipherSuite,
		handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, true, true},
		handshakeCachePullRule{handshake.TypeClientKeyExchange, cfg.initialEpoch, true, false},
		handshakeCachePullRule{handshake.TypeCertificateVerify, cfg.initialEpoch, true, true},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	// Validate type
	var clientKeyExchange *handshake.MessageClientKeyExchange
	if clientKeyExchange, ok = msgs[handshake.TypeClientKeyExchange].(*handshake.MessageClientKeyExchange); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if h, hasCert := msgs[handshake.TypeCertificate].(*handshake.MessageCertificate); hasCert {
		state.PeerCertificates = h.Certificate
		// If the client offer its certificate, just disable session resumption.
		// Otherwise, we have to store the certificate identitfication and expire time.
		// And we have to check whether this certificate expired, revoked or changed.
		//
		// https://curl.se/docs/CVE-2016-5419.html
		state.SessionID = nil
	}

	//nolint:nestif
	if verify, hasVerify := msgs[handshake.TypeCertificateVerify].(*handshake.MessageCertificateVerify); hasVerify {
		if state.PeerCertificates == nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, dtlserrors.ErrCertificateVerifyNoCertificate
		}

		plainText := cache.pullAndMerge(
			handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificateRequest, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeServerHelloDone, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeClientKeyExchange, cfg.initialEpoch, true, false},
		)

		// Verify that the pair of hash algorithm and signiture is listed.
		var validSignatureScheme bool
		for _, ss := range cfg.localSignatureSchemes {
			if ss.Hash == verify.HashAlgorithm && ss.Signature == verify.SignatureAlgorithm {
				validSignatureScheme = true

				break
			}
		}
		if !validSignatureScheme {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrNoAvailableSignatureSchemes
		}

		if err := verifyCertificateVerify(
			plainText,
			verify.HashAlgorithm,
			verify.SignatureAlgorithm,
			verify.Signature,
			state.PeerCertificates,
		); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
		}
		var chains [][]*x509.Certificate
		var err error
		var verified bool
		if cfg.clientAuth >= VerifyClientCertIfGiven {
			// Use cert-specific algorithms if present, otherwise fall back to signature_algorithms per RFC 8446
			certAlgs := cfg.localCertSignatureSchemes
			if len(certAlgs) == 0 {
				certAlgs = cfg.localSignatureSchemes
			}
			if chains, err = verifyClientCert(state.PeerCertificates, cfg.clientCAs, certAlgs); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
			}
			verified = true
		}
		if cfg.verifyPeerCertificate != nil {
			if err := cfg.verifyPeerCertificate(state.PeerCertificates, chains); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
			}
		}
		state.PeerCertificatesVerified = verified
	} else if state.PeerCertificates != nil {
		// A certificate was received, but we haven't seen a CertificateVerify
		// keep reading until we receive one
		return 0, nil, nil
	}

	if !state.CipherSuite.IsInitialized() { //nolint:nestif
		serverRandom := state.LocalRandom.MarshalFixed()
		clientRandom := state.RemoteRandom.MarshalFixed()

		var err error
		var preMasterSecret []byte
		if state.CipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypePreSharedKey {
			var psk []byte
			if psk, err = cfg.localPSKCallback(clientKeyExchange.IdentityHint); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
			state.IdentityHint = clientKeyExchange.IdentityHint
			switch state.CipherSuite.KeyExchangeAlgorithm() {
			case CipherSuiteKeyExchangeAlgorithmPsk:
				preMasterSecret = prf.PSKPreMasterSecret(psk)
			case (CipherSuiteKeyExchangeAlgorithmPsk | CipherSuiteKeyExchangeAlgorithmEcdhe):
				if preMasterSecret, err = prf.EcdhePSKPreMasterSecret(
					psk,
					clientKeyExchange.PublicKey,
					state.LocalKeypair.PrivateKey,
					state.LocalKeypair.Curve,
				); err != nil {
					return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
				}
			default:
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, dtlserrors.ErrInvalidCipherSuite
			}
		} else {
			preMasterSecret, err = prf.PreMasterSecret(
				clientKeyExchange.PublicKey,
				state.LocalKeypair.PrivateKey,
				state.LocalKeypair.Curve,
			)
			if err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
			}
		}

		if state.ExtendedMasterSecret {
			var sessionHash []byte
			sessionHash, err = cache.sessionHash(state.CipherSuite.HashFunc(), cfg.initialEpoch)
			if err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}

			state.MasterSecret, err = prf.ExtendedMasterSecret(preMasterSecret, sessionHash, state.CipherSuite.HashFunc())
			if err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
		} else {
			state.MasterSecret, err = prf.MasterSecret(
				preMasterSecret,
				clientRandom[:],
				serverRandom[:],
				state.CipherSuite.HashFunc(),
			)
			if err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
		}

		if err := state.CipherSuite.Init(state.MasterSecret, clientRandom[:], serverRandom[:], false); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		cfg.writeKeyLog(keyLogLabelTLS12, clientRandom[:], state.MasterSecret)
	}

	if len(state.SessionID) > 0 {
		s := Session{
			ID:     state.SessionID,
			Secret: state.MasterSecret,
		}
		cfg.log.Tracef("[handshake] save new session: %x", s.ID)
		if err := cfg.sessionStore.Set(state.SessionID, s); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	// Now, encrypted packets can be handled
	if err := conn.handleQueuedPackets(ctx); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	seq, msgs, ok = cache.fullPullMap(seq, state.CipherSuite,
		handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, true, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}
	state.HandshakeRecvSequence = seq

	if _, ok = msgs[handshake.TypeFinished].(*handshake.MessageFinished); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if state.CipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeAnonymous { //nolint:nestif
		if cfg.verifyConnection != nil {
			stateSnapshot, err := generateState(state)
			if err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
			if err := cfg.verifyConnection(stateSnapshot); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
			}
		}

		return flight6, nil, nil
	}

	switch cfg.clientAuth {
	case RequireAnyClientCert:
		if state.PeerCertificates == nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, dtlserrors.ErrClientCertificateRequired
		}
	case VerifyClientCertIfGiven:
		if state.PeerCertificates != nil && !state.PeerCertificatesVerified {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, dtlserrors.ErrClientCertificateNotVerified
		}
	case RequireAndVerifyClientCert:
		if state.PeerCertificates == nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, dtlserrors.ErrClientCertificateRequired
		}
		if !state.PeerCertificatesVerified {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, dtlserrors.ErrClientCertificateNotVerified
		}
	case NoClientCert, RequestClientCert:
		// go to flight6
	}
	if cfg.verifyConnection != nil {
		stateSnapshot, err := generateState(state)
		if err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		if err := cfg.verifyConnection(stateSnapshot); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
		}
	}

	return flight6, nil, nil
}

//nolint:gocognit,cyclop,maintidx
func flight4Generate(
	_ flightConn,
	state *dtlsstate.State,
	_ *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *alert.Alert, error) {
	extensions := []extension.Extension{}

	if (cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		cfg.extendedMasterSecret == RequireExtendedMasterSecret) && state.ExtendedMasterSecret {
		extensions = append(extensions, &extension.UseExtendedMasterSecret{
			Supported: true,
		})
	}
	if state.GetSRTPProtectionProfile() != 0 {
		extensions = append(extensions, &extension.UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{state.GetSRTPProtectionProfile()},
			MasterKeyIdentifier: cfg.localSRTPMasterKeyIdentifier,
		})
	}
	if state.RemoteSupportsRenegotiation {
		extensions = append(extensions, &extension.RenegotiationInfo{
			RenegotiatedConnection: 0,
		})
	}
	if state.CipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate {
		extensions = append(extensions, &extension.SupportedPointFormats{
			PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
		})
	}

	selectedProto, err := extension.ALPNProtocolSelection(cfg.supportedProtocols, state.PeerSupportedProtocols)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.NoApplicationProtocol}, err
	}
	if selectedProto != "" {
		extensions = append(extensions, &extension.ALPN{
			ProtocolNameList: []string{selectedProto},
		})
		state.NegotiatedProtocol = selectedProto
	}

	// If we have a connection ID generator, we are willing to use connection
	// IDs. We already know whether the client supports connection IDs from
	// parsing the ClientHello, so avoid setting local connection ID if the
	// client won't send it.
	if cfg.connectionIDGenerator != nil && state.RemoteConnectionID != nil {
		state.SetLocalConnectionID(cfg.connectionIDGenerator())
		extensions = append(extensions, &extension.ConnectionID{CID: state.GetLocalConnectionID()})
	}

	var pkts []*packet
	cipherSuiteID := uint16(state.CipherSuite.ID())

	if cfg.sessionStore != nil {
		state.SessionID = make([]byte, sessionLength)
		if _, err := rand.Read(state.SessionID); err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	serverHello := &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		Random:            state.LocalRandom,
		SessionID:         state.SessionID,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: defaultCompressionMethods()[0],
		Extensions:        extensions,
	}

	var content handshake.Handshake

	if cfg.serverHelloMessageHook != nil {
		content = handshake.Handshake{Message: cfg.serverHelloMessageHook(*serverHello)}
	} else {
		content = handshake.Handshake{Message: serverHello}
	}

	pkts = append(pkts, &packet{
		record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
			},
			Content: &content,
		},
	})

	switch {
	case state.CipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate:
		certificate, err := cfg.getCertificate(&ClientHelloInfo{
			ServerName:   state.ServerName,
			CipherSuites: []ciphersuite.ID{state.CipherSuite.ID()},
			RandomBytes:  state.RemoteRandom.RandomBytes,
		})
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
		}

		pkts = append(pkts, &packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageCertificate{
						Certificate: certificate.Certificate,
					},
				},
			},
		})

		serverRandom := state.LocalRandom.MarshalFixed()
		clientRandom := state.RemoteRandom.MarshalFixed()

		signer, ok := certificate.PrivateKey.(crypto.Signer)
		if !ok {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, dtlserrors.ErrInvalidPrivateKey
		}

		// Find compatible signature scheme
		signatureHashAlgo, err := signaturehash.SelectSignatureScheme(cfg.localSignatureSchemes, signer)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, err
		}

		signature, err := generateKeySignature(
			clientRandom[:],
			serverRandom[:],
			state.LocalKeypair.PublicKey,
			state.NamedCurve,
			signer,
			signatureHashAlgo.Hash,
			signatureHashAlgo.Signature,
		)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		state.LocalKeySignature = signature

		pkts = append(pkts, &packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageServerKeyExchange{
						EllipticCurveType:  elliptic.CurveTypeNamedCurve,
						NamedCurve:         state.NamedCurve,
						PublicKey:          state.LocalKeypair.PublicKey,
						HashAlgorithm:      signatureHashAlgo.Hash,
						SignatureAlgorithm: signatureHashAlgo.Signature,
						Signature:          state.LocalKeySignature,
					},
				},
			},
		})

		if cfg.clientAuth > NoClientCert {
			// An empty list of certificateAuthorities signals to
			// the client that it may send any certificate in response
			// to our request. When we know the CAs we trust, then
			// we can send them down, so that the client can choose
			// an appropriate certificate to give to us.
			var certificateAuthorities [][]byte
			if cfg.clientCAs != nil {
				// nolint:staticcheck // ignoring tlsCert.RootCAs.Subjects is deprecated ERR
				// because cert does not come from SystemCertPool and it's ok if certificate
				// authorities is empty.
				certificateAuthorities = cfg.clientCAs.Subjects()
			}

			certReq := &handshake.MessageCertificateRequest{
				CertificateTypes:            []clientcertificate.Type{clientcertificate.RSASign, clientcertificate.ECDSASign},
				SignatureHashAlgorithms:     cfg.localSignatureSchemes,
				CertificateAuthoritiesNames: certificateAuthorities,
			}

			var content handshake.Handshake

			if cfg.certificateRequestMessageHook != nil {
				content = handshake.Handshake{Message: cfg.certificateRequestMessageHook(*certReq)}
			} else {
				content = handshake.Handshake{Message: certReq}
			}

			pkts = append(pkts, &packet{
				record: &recordlayer.RecordLayer{
					Header: recordlayer.Header{
						Version: protocol.Version1_2,
					},
					Content: &content,
				},
			})
		}
	case cfg.localPSKIdentityHint != nil ||
		state.CipherSuite.KeyExchangeAlgorithm().Has(CipherSuiteKeyExchangeAlgorithmEcdhe):
		// To help the client in selecting which identity to use, the server
		// can provide a "PSK identity hint" in the ServerKeyExchange message.
		// If no hint is provided and cipher suite doesn't use elliptic curve,
		// the ServerKeyExchange message is omitted.
		//
		// https://tools.ietf.org/html/rfc4279#section-2
		srvExchange := &handshake.MessageServerKeyExchange{
			IdentityHint: cfg.localPSKIdentityHint,
		}
		if state.CipherSuite.KeyExchangeAlgorithm().Has(CipherSuiteKeyExchangeAlgorithmEcdhe) {
			srvExchange.EllipticCurveType = elliptic.CurveTypeNamedCurve
			srvExchange.NamedCurve = state.NamedCurve
			srvExchange.PublicKey = state.LocalKeypair.PublicKey
		}
		pkts = append(pkts, &packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: srvExchange,
				},
			},
		})
	}

	pkts = append(pkts, &packet{
		record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				Message: &handshake.MessageServerHelloDone{},
			},
		},
	})

	return pkts, nil, nil
}
