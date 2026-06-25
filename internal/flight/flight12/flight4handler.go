// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlscrypto "github.com/pion/dtls/v3/internal/handshakecrypto"
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
	conn dtlsflight.Conn,
	state *dtlsstate.State,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (dtlsflight.Flight12, *alert.Alert, error) {
	seq, msgs, ok := cache.FullPullMap(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificate, Epoch: cfg.InitialEpoch, IsClient: true, Optional: true},        //nolint:lll
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientKeyExchange, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false}, //nolint:lll
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificateVerify, Epoch: cfg.InitialEpoch, IsClient: true, Optional: true},  //nolint:lll
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

		//nolint:dupl
		plainText := cache.PullAndMerge(
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},         //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},        //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificate, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},        //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerKeyExchange, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},  //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificateRequest, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false}, //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHelloDone, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},    //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificate, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},         //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientKeyExchange, Epoch: cfg.InitialEpoch, IsClient: true, Optional: false},   //nolint:lll
		)

		// Verify that the pair of hash algorithm and signiture is listed.
		var validSignatureScheme bool
		for _, ss := range cfg.LocalSignatureSchemes {
			if ss.Hash == verify.HashAlgorithm && ss.Signature == verify.SignatureAlgorithm {
				validSignatureScheme = true

				break
			}
		}
		if !validSignatureScheme {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrNoAvailableSignatureSchemes
		}

		if err := dtlscrypto.VerifyCertificateVerify(
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
		if cfg.ClientAuth >= dtlsconfig.VerifyClientCertIfGiven {
			// Use cert-specific algorithms if present, otherwise fall back to signature_algorithms per RFC 8446
			certAlgs := cfg.LocalCertSignatureSchemes
			if len(certAlgs) == 0 {
				certAlgs = cfg.LocalSignatureSchemes
			}
			if chains, err = dtlscrypto.VerifyClientCert(state.PeerCertificates, cfg.ClientCAs, certAlgs); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
			}
			verified = true
		}
		if cfg.VerifyPeerCertificate != nil {
			if err := cfg.VerifyPeerCertificate(state.PeerCertificates, chains); err != nil {
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
		if state.CipherSuite.AuthenticationType() == ciphersuite.AuthenticationTypePreSharedKey {
			var psk []byte
			if psk, err = cfg.LocalPSKCallback(clientKeyExchange.IdentityHint); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
			state.IdentityHint = clientKeyExchange.IdentityHint
			switch state.CipherSuite.KeyExchangeAlgorithm() {
			case ciphersuite.KeyExchangeAlgorithmPsk:
				preMasterSecret = prf.PSKPreMasterSecret(psk)
			case (ciphersuite.KeyExchangeAlgorithmPsk | ciphersuite.KeyExchangeAlgorithmEcdhe):
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
			sessionHash, err = cache.SessionHash(state.CipherSuite.HashFunc(), cfg.InitialEpoch)
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
		cfg.WriteKeyLog(keyLogLabelTLS12, clientRandom[:], state.MasterSecret)
	}

	if len(state.SessionID) > 0 {
		cfg.Log.Tracef("[handshake] save new session: %x", state.SessionID)
		if err := cfg.SetSession(state.SessionID, state.SessionID, state.MasterSecret); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	// Now, encrypted packets can be handled
	if err := conn.HandleQueuedPackets(ctx); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	seq, msgs, ok = cache.FullPullMap(seq, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeFinished, Epoch: cfg.InitialEpoch + 1, IsClient: true, Optional: false}, //nolint:lll
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}
	state.HandshakeRecvSequence = seq

	if _, ok = msgs[handshake.TypeFinished].(*handshake.MessageFinished); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if state.CipherSuite.AuthenticationType() == ciphersuite.AuthenticationTypeAnonymous { //nolint:nestif
		if cfg.VerifyConnection != nil {
			if err := cfg.VerifyConnection(state); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
			}
		}

		return dtlsflight.Flight6, nil, nil
	}

	switch cfg.ClientAuth {
	case dtlsconfig.RequireAnyClientCert:
		if state.PeerCertificates == nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, dtlserrors.ErrClientCertificateRequired
		}
	case dtlsconfig.VerifyClientCertIfGiven:
		if state.PeerCertificates != nil && !state.PeerCertificatesVerified {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, dtlserrors.ErrClientCertificateNotVerified
		}
	case dtlsconfig.RequireAndVerifyClientCert:
		if state.PeerCertificates == nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, dtlserrors.ErrClientCertificateRequired
		}
		if !state.PeerCertificatesVerified {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, dtlserrors.ErrClientCertificateNotVerified
		}
	case dtlsconfig.NoClientCert, dtlsconfig.RequestClientCert:
		// go to Flight6
	}
	if cfg.VerifyConnection != nil {
		if err := cfg.VerifyConnection(state); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
		}
	}

	return dtlsflight.Flight6, nil, nil
}

//nolint:gocognit,cyclop,maintidx
func flight4Generate(
	_ dtlsflight.Conn,
	state *dtlsstate.State,
	_ *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	extensions := []extension.Extension{}

	if (cfg.ExtendedMasterSecret == dtlsconfig.RequestExtendedMasterSecret ||
		cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret) && state.ExtendedMasterSecret {
		extensions = append(extensions, &extension.UseExtendedMasterSecret{
			Supported: true,
		})
	}
	if state.GetSRTPProtectionProfile() != 0 {
		extensions = append(extensions, &extension.UseSRTP{
			ProtectionProfiles:  []dtlsconfig.SRTPProtectionProfile{state.GetSRTPProtectionProfile()},
			MasterKeyIdentifier: cfg.LocalSRTPMasterKeyIdentifier,
		})
	}
	if state.RemoteSupportsRenegotiation {
		extensions = append(extensions, &extension.RenegotiationInfo{
			RenegotiatedConnection: 0,
		})
	}
	if state.CipherSuite.AuthenticationType() == ciphersuite.AuthenticationTypeCertificate {
		extensions = append(extensions, &extension.SupportedPointFormats{
			PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
		})
	}

	selectedProto, err := extension.ALPNProtocolSelection(cfg.SupportedProtocols, state.PeerSupportedProtocols)
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
	if cfg.ConnectionIDGenerator != nil && state.RemoteConnectionID != nil {
		state.SetLocalConnectionID(cfg.ConnectionIDGenerator())
		extensions = append(extensions, &extension.ConnectionID{CID: state.GetLocalConnectionID()})
	}

	var pkts []*dtlsflight.Packet
	cipherSuiteID := uint16(state.CipherSuite.ID())

	if cfg.HasSessionStore {
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
		CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
		Extensions:        extensions,
	}

	var content handshake.Handshake

	if cfg.ServerHelloMessageHook != nil {
		content = handshake.Handshake{Message: cfg.ServerHelloMessageHook(*serverHello)}
	} else {
		content = handshake.Handshake{Message: serverHello}
	}

	pkts = append(pkts, &dtlsflight.Packet{
		Record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
			},
			Content: &content,
		},
	})

	switch {
	case state.CipherSuite.AuthenticationType() == ciphersuite.AuthenticationTypeCertificate:
		certificate, err := cfg.GetCertificate(&dtlsconfig.ClientHelloInfo{
			ServerName:   state.ServerName,
			CipherSuites: []ciphersuite.ID{state.CipherSuite.ID()},
			RandomBytes:  state.RemoteRandom.RandomBytes,
		})
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
		}

		pkts = append(pkts, &dtlsflight.Packet{
			Record: &recordlayer.RecordLayer{
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
		signatureHashAlgo, err := signaturehash.SelectSignatureScheme(cfg.LocalSignatureSchemes, signer)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, err
		}

		signature, err := dtlscrypto.GenerateKeySignature(
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

		pkts = append(pkts, &dtlsflight.Packet{
			Record: &recordlayer.RecordLayer{
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

			certReq := &handshake.MessageCertificateRequest{
				CertificateTypes:            []clientcertificate.Type{clientcertificate.RSASign, clientcertificate.ECDSASign},
				SignatureHashAlgorithms:     cfg.LocalSignatureSchemes,
				CertificateAuthoritiesNames: certificateAuthorities,
			}

			var content handshake.Handshake

			if cfg.CertificateRequestMessageHook != nil {
				content = handshake.Handshake{Message: cfg.CertificateRequestMessageHook(*certReq)}
			} else {
				content = handshake.Handshake{Message: certReq}
			}

			pkts = append(pkts, &dtlsflight.Packet{
				Record: &recordlayer.RecordLayer{
					Header: recordlayer.Header{
						Version: protocol.Version1_2,
					},
					Content: &content,
				},
			})
		}
	case cfg.LocalPSKIdentityHint != nil ||
		state.CipherSuite.KeyExchangeAlgorithm().Has(ciphersuite.KeyExchangeAlgorithmEcdhe):
		// To help the client in selecting which identity to use, the server
		// can provide a "PSK identity hint" in the ServerKeyExchange message.
		// If no hint is provided and cipher suite doesn't use elliptic curve,
		// the ServerKeyExchange message is omitted.
		//
		// https://tools.ietf.org/html/rfc4279#section-2
		srvExchange := &handshake.MessageServerKeyExchange{
			IdentityHint: cfg.LocalPSKIdentityHint,
		}
		if state.CipherSuite.KeyExchangeAlgorithm().Has(ciphersuite.KeyExchangeAlgorithmEcdhe) {
			srvExchange.EllipticCurveType = elliptic.CurveTypeNamedCurve
			srvExchange.NamedCurve = state.NamedCurve
			srvExchange.PublicKey = state.LocalKeypair.PublicKey
		}
		pkts = append(pkts, &dtlsflight.Packet{
			Record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: srvExchange,
				},
			},
		})
	}

	pkts = append(pkts, &dtlsflight.Packet{
		Record: &recordlayer.RecordLayer{
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
