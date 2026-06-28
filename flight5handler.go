// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func flight5Parse(
	_ context.Context,
	conn flightConn,
	state *dtlsstate.State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *alert.Alert, error) {
	_, msgs, ok := cache.fullPullMap(state.HandshakeRecvSequence, state.CipherSuite,
		handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, false, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	var finished *handshake.MessageFinished
	if finished, ok = msgs[handshake.TypeFinished].(*handshake.MessageFinished); !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
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
		handshakeCachePullRule{handshake.TypeCertificateVerify, cfg.initialEpoch, true, false},
		handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, true, false},
	)

	expectedVerifyData, err := prf.VerifyDataServer(state.MasterSecret, plainText, state.CipherSuite.HashFunc())
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if !bytes.Equal(expectedVerifyData, finished.VerifyData) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrVerifyDataMismatch
	}

	if len(state.SessionID) > 0 {
		s := Session{
			ID:     state.SessionID,
			Secret: state.MasterSecret,
		}
		cfg.log.Tracef("[handshake] save new session: %x", s.ID)
		if err := cfg.sessionStore.Set(conn.sessionKey(), s); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	return flight5, nil, nil
}

//nolint:gocognit,cyclop,maintidx
func flight5Generate(
	conn flightConn,
	state *dtlsstate.State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *alert.Alert, error) {
	var signer crypto.Signer
	var pkts []*packet
	if state.RemoteRequestedCertificate { //nolint:nestif
		_, msgs, ok := cache.fullPullMap(state.HandshakeRecvSequence-2, state.CipherSuite,
			handshakeCachePullRule{handshake.TypeCertificateRequest, cfg.initialEpoch, false, false})
		if !ok {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrClientCertificateRequired //nolint:lll
		}
		reqInfo := CertificateRequestInfo{}
		if r, ok2 := msgs[handshake.TypeCertificateRequest].(*handshake.MessageCertificateRequest); ok2 {
			reqInfo.AcceptableCAs = r.CertificateAuthoritiesNames
		} else {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrClientCertificateRequired //nolint:lll
		}
		certificate, err := cfg.getClientCertificate(&reqInfo)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
		}
		if certificate == nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrNotAcceptableCertificateChain //nolint:lll
		}
		if certificate.Certificate != nil {
			signer, ok = certificate.PrivateKey.(crypto.Signer)
			if !ok {
				return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrInvalidPrivateKey
			}
		}
		pkts = append(pkts,
			&packet{
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
	}

	clientKeyExchange := &handshake.MessageClientKeyExchange{}
	if cfg.localPSKCallback == nil {
		clientKeyExchange.PublicKey = state.LocalKeypair.PublicKey
	} else {
		clientKeyExchange.IdentityHint = cfg.localPSKIdentityHint
	}
	if state != nil && state.LocalKeypair != nil && len(state.LocalKeypair.PublicKey) > 0 {
		clientKeyExchange.PublicKey = state.LocalKeypair.PublicKey
	}

	pkts = append(pkts,
		&packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: clientKeyExchange,
				},
			},
		})

	serverKeyExchangeData := cache.pullAndMerge(
		handshakeCachePullRule{handshake.TypeServerKeyExchange, cfg.initialEpoch, false, false},
	)

	serverKeyExchange := &handshake.MessageServerKeyExchange{}

	// handshakeMessageServerKeyExchange is optional for PSK
	if len(serverKeyExchangeData) == 0 {
		alertPtr, err := handleServerKeyExchange(conn, state, cfg, &handshake.MessageServerKeyExchange{})
		if err != nil {
			return nil, alertPtr, err
		}
	} else {
		rawHandshake := &handshake.Handshake{
			KeyExchangeAlgorithm: state.CipherSuite.KeyExchangeAlgorithm(),
		}
		err := rawHandshake.Unmarshal(serverKeyExchangeData)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage}, err
		}

		switch h := rawHandshake.Message.(type) {
		case *handshake.MessageServerKeyExchange:
			serverKeyExchange = h
		default:
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage}, dtlserrors.ErrInvalidContentType
		}
	}

	// Append not-yet-sent packets
	merged := []byte{}
	seqPred := uint16(state.HandshakeSendSequence) //nolint:gosec // G115
	for _, p := range pkts {
		h, ok := p.record.Content.(*handshake.Handshake)
		if !ok {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, dtlserrors.ErrInvalidContentType
		}
		h.Header.MessageSequence = seqPred
		seqPred++
		raw, err := h.Marshal()
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		merged = append(merged, raw...)
	}

	if alertPtr, err := initializeCipherSuite(state, cache, cfg, serverKeyExchange, merged); err != nil {
		return nil, alertPtr, err
	}

	// If the client has sent a certificate with signing ability, a digitally-signed
	// CertificateVerify message is sent to explicitly verify possession of the
	// private key in the certificate.
	if state.RemoteRequestedCertificate && signer != nil {
		plainText := append(cache.pullAndMerge(
			handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificateRequest, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeServerHelloDone, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeClientKeyExchange, cfg.initialEpoch, true, false},
		), merged...)

		// Find compatible signature scheme

		signatureHashAlgo, err := signaturehash.SelectSignatureScheme(state.RemoteCertRequestAlgs, signer)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, err
		}

		certVerify, err := generateCertificateVerify(plainText, signer, signatureHashAlgo.Hash, signatureHashAlgo.Signature)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		state.LocalCertificatesVerify = certVerify

		pkt := &packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageCertificateVerify{
						HashAlgorithm:      signatureHashAlgo.Hash,
						SignatureAlgorithm: signatureHashAlgo.Signature,
						Signature:          state.LocalCertificatesVerify,
					},
				},
			},
		}
		pkts = append(pkts, pkt)

		h, ok := pkt.record.Content.(*handshake.Handshake)
		if !ok {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, dtlserrors.ErrInvalidContentType
		}
		h.Header.MessageSequence = seqPred
		// seqPred++ // this is the last use of seqPred
		raw, err := h.Marshal()
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		merged = append(merged, raw...)
	}

	pkts = append(pkts,
		&packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &protocol.ChangeCipherSpec{},
			},
		})

	if len(state.LocalVerifyData) == 0 {
		plainText := cache.pullAndMerge(
			handshakeCachePullRule{handshake.TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificateRequest, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeServerHelloDone, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeClientKeyExchange, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeCertificateVerify, cfg.initialEpoch, true, false},
			handshakeCachePullRule{handshake.TypeFinished, cfg.initialEpoch + 1, true, false},
		)

		var err error
		state.LocalVerifyData, err = prf.VerifyDataClient(
			state.MasterSecret,
			append(plainText, merged...),
			state.CipherSuite.HashFunc(),
		)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	pkts = append(pkts,
		&packet{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
					Epoch:   1,
				},
				Content: &handshake.Handshake{
					Message: &handshake.MessageFinished{
						VerifyData: state.LocalVerifyData,
					},
				},
			},
			shouldWrapCID:            len(state.RemoteConnectionID) > 0,
			shouldEncrypt:            true,
			resetLocalSequenceNumber: true,
		})

	return pkts, nil, nil
}

//nolint:gocognit,cyclop
func initializeCipherSuite(
	state *dtlsstate.State,
	cache *handshakeCache,
	cfg *handshakeConfig,
	handshakeKeyExchange *handshake.MessageServerKeyExchange,
	sendingPlainText []byte,
) (*alert.Alert, error) {
	if state.CipherSuite.IsInitialized() {
		return nil, nil //nolint
	}

	clientRandom := state.LocalRandom.MarshalFixed()
	serverRandom := state.RemoteRandom.MarshalFixed()

	var err error

	if state.ExtendedMasterSecret {
		var sessionHash []byte
		sessionHash, err = cache.sessionHash(state.CipherSuite.HashFunc(), cfg.initialEpoch, sendingPlainText)
		if err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}

		state.MasterSecret, err = prf.ExtendedMasterSecret(state.PreMasterSecret, sessionHash, state.CipherSuite.HashFunc())
		if err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
		}
	} else {
		state.MasterSecret, err = prf.MasterSecret(
			state.PreMasterSecret,
			clientRandom[:],
			serverRandom[:],
			state.CipherSuite.HashFunc(),
		)
		if err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	if state.CipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate { //nolint:nestif
		// Verify that the pair of hash algorithm and signiture is listed.
		var validSignatureScheme bool
		for _, ss := range cfg.localSignatureSchemes {
			if ss.Hash == handshakeKeyExchange.HashAlgorithm && ss.Signature == handshakeKeyExchange.SignatureAlgorithm {
				validSignatureScheme = true

				break
			}
		}
		if !validSignatureScheme {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrNoAvailableSignatureSchemes //nolint:lll
		}

		expectedMsg := valueKeyMessage(
			clientRandom[:],
			serverRandom[:],
			handshakeKeyExchange.PublicKey,
			handshakeKeyExchange.NamedCurve,
		)
		if err = verifyKeySignature(
			expectedMsg,
			handshakeKeyExchange.Signature,
			handshakeKeyExchange.HashAlgorithm,
			handshakeKeyExchange.SignatureAlgorithm,
			state.PeerCertificates,
		); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
		}
		var chains [][]*x509.Certificate
		if !cfg.insecureSkipVerify {
			certAlgs := cfg.localCertSignatureSchemes
			if len(certAlgs) == 0 {
				certAlgs = cfg.localSignatureSchemes
			}
			if chains, err = verifyServerCert(state.PeerCertificates, cfg.rootCAs, cfg.serverName, certAlgs); err != nil {
				return &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
			}
		}
		if cfg.verifyPeerCertificate != nil {
			if err = cfg.verifyPeerCertificate(state.PeerCertificates, chains); err != nil {
				return &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
			}
		}
	}
	if cfg.verifyConnection != nil {
		stateSnapshot, errC := generateState(state)
		if errC != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, errC
		}
		if errC = cfg.verifyConnection(stateSnapshot); errC != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, errC
		}
	}

	if err = state.CipherSuite.Init(state.MasterSecret, clientRandom[:], serverRandom[:], true); err != nil {
		return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	cfg.writeKeyLog(keyLogLabelTLS12, clientRandom[:], state.MasterSecret)

	return nil, nil //nolint
}
