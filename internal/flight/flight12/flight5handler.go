// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlscrypto "github.com/pion/dtls/v3/internal/handshakecrypto"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

func flight5Parse(
	_ context.Context,
	conn dtlsflight.Conn,
	state *dtlsstate.State12,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (Flight, *alert.Alert, error) {
	pull := cache.FullPullMapItems(state.HandshakeRecvSequence, state.CipherSuite,
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
	plainText := cache.PullAndMerge(handshakeRulesThroughClientFinished(cfg.InitialEpoch)...)

	expectedVerifyData, err := prf.VerifyDataServer(state.MasterSecret, plainText, state.CipherSuite.HashFunc())
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if !bytes.Equal(expectedVerifyData, finished.VerifyData) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrVerifyDataMismatch
	}

	if len(state.SessionID) > 0 {
		cfg.Log.Tracef("[handshake] save new session: %x", state.SessionID)
		if err := cfg.SetSession(conn.SessionKey(), state.SessionID, state.MasterSecret); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	return Flight5, nil, nil
}

//nolint:gocognit,cyclop,maintidx
func flight5Generate(
	conn dtlsflight.Conn,
	state *dtlsstate.State12,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	var signer crypto.Signer
	var pkts []*dtlsflight.Outbound
	if state.RemoteRequestedCertificate { //nolint:nestif
		pull := cache.FullPullMapItems(state.HandshakeRecvSequence-2, state.CipherSuite,
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificateRequest, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false}) //nolint:lll
		if pull.Err != nil {
			return nil, nil, pull.Err
		}
		if !pull.Ready {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrClientCertificateRequired //nolint:lll
		}
		reqInfo := dtlsconfig.CertificateRequestInfo{Version: protocol.Version1_2}
		if r, ok2 := pull.Messages[handshake.TypeCertificateRequest].(*handshake.MessageCertificateRequest); ok2 {
			reqInfo.AcceptableCAs = make([][]byte, len(r.CertificateAuthoritiesNames))
			for i := range r.CertificateAuthoritiesNames {
				reqInfo.AcceptableCAs[i] = bytes.Clone(r.CertificateAuthoritiesNames[i])
			}
		} else {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrClientCertificateRequired //nolint:lll
		}
		certificate, err := cfg.GetClientCertificate(&reqInfo)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
		}
		if certificate == nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrNotAcceptableCertificateChain //nolint:lll
		}
		if certificate.Certificate != nil {
			var ok bool
			signer, ok = certificate.PrivateKey.(crypto.Signer)
			if !ok {
				return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, dtlserrors.ErrInvalidPrivateKey
			}
		}
		pkts = append(pkts,
			&dtlsflight.Outbound{
				Content: &handshake.Handshake{
					Message: &handshake.MessageCertificate{
						Certificate: certificate.Certificate,
					},
				},
			})
	}

	clientKeyExchange := &handshake.MessageClientKeyExchange{}
	if cfg.LocalPSKCallback == nil {
		clientKeyExchange.PublicKey = state.LocalKeypair.PublicKey
	} else {
		clientKeyExchange.IdentityHint = cfg.LocalPSKIdentityHint
	}
	if state != nil && state.LocalKeypair != nil && len(state.LocalKeypair.PublicKey) > 0 {
		clientKeyExchange.PublicKey = state.LocalKeypair.PublicKey
	}

	pkts = append(pkts,
		&dtlsflight.Outbound{
			Content: &handshake.Handshake{
				Message: clientKeyExchange,
			},
		})

	serverKeyExchange := state.RemoteServerKeyExchange()

	// handshakeMessageServerKeyExchange is optional for PSK
	if serverKeyExchange == nil {
		serverKeyExchange = &handshake.MessageServerKeyExchange{}
		alertPtr, err := handleServerKeyExchange(conn, state, cfg, serverKeyExchange)
		if err != nil {
			return nil, alertPtr, err
		}
	}

	// Append not-yet-sent packets
	merged := []byte{}
	seqPred := uint16(state.HandshakeSendSequence) //nolint:gosec // G115
	for _, p := range pkts {
		h, ok := p.Content.(*handshake.Handshake)
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
		plainText := append(
			cache.PullAndMerge(handshakeRulesThroughClientKeyExchange(cfg.InitialEpoch)...),
			merged...,
		)

		// Find compatible signature scheme

		signatureHashAlgo, err := signaturehash.SelectSignatureScheme(
			state.RemoteCertRequestAlgs,
			signer,
			protocol.Version1_2,
		)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, err
		}

		certVerify, err := dtlscrypto.GenerateCertificateVerify(
			plainText,
			signer,
			signatureHashAlgo.Hash,
			signatureHashAlgo.Signature,
		)
		if err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		state.LocalCertificatesVerify = certVerify

		pkt := &dtlsflight.Outbound{
			Content: &handshake.Handshake{
				Message: &handshake.MessageCertificateVerify{
					HashAlgorithm:      signatureHashAlgo.Hash,
					SignatureAlgorithm: signatureHashAlgo.Signature,
					Signature:          state.LocalCertificatesVerify,
				},
			},
		}
		pkts = append(pkts, pkt)

		h, ok := pkt.Content.(*handshake.Handshake)
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
		&dtlsflight.Outbound{
			Content: &protocol.ChangeCipherSpec{},
		})

	if len(state.LocalVerifyData) == 0 {
		plainText := cache.PullAndMerge(handshakeRulesThroughClientFinished(cfg.InitialEpoch)...)

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
		&dtlsflight.Outbound{
			Epoch: 1,
			Content: &handshake.Handshake{
				Message: &handshake.MessageFinished{
					VerifyData: state.LocalVerifyData,
				},
			},
			Protection: dtlsflight.ProtectionCiphertext,
		})

	return pkts, nil, nil
}

//nolint:gocognit,cyclop
func initializeCipherSuite(
	state *dtlsstate.State12,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	handshakeKeyExchange *handshake.MessageServerKeyExchange,
	sendingPlainText []byte,
) (*alert.Alert, error) {
	if state.Protection != nil {
		return nil, nil //nolint
	}

	clientRandom := state.LocalRandom.MarshalFixed()
	serverRandom := state.RemoteRandom.MarshalFixed()

	var err error

	if state.ExtendedMasterSecret {
		var sessionHash []byte
		sessionHash, err = cache.SessionHash(state.CipherSuite.HashFunc(), cfg.InitialEpoch, sendingPlainText)
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

	if state.CipherSuite.AuthenticationType() == cryptosuite.AuthenticationTypeCertificate { //nolint:nestif
		// Verify that the pair of hash algorithm and signiture is listed.
		var validSignatureScheme bool
		for _, ss := range cfg.LocalSignatureSchemes {
			if ss.Hash == handshakeKeyExchange.HashAlgorithm && ss.Signature == handshakeKeyExchange.SignatureAlgorithm {
				validSignatureScheme = true

				break
			}
		}
		if !validSignatureScheme {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrNoAvailableSignatureSchemes //nolint:lll
		}

		expectedMsg := dtlscrypto.ValueKeyMessage(
			clientRandom[:],
			serverRandom[:],
			handshakeKeyExchange.PublicKey,
			handshakeKeyExchange.NamedCurve,
		)
		if err = dtlscrypto.VerifyKeySignature(
			expectedMsg,
			handshakeKeyExchange.Signature,
			handshakeKeyExchange.HashAlgorithm,
			handshakeKeyExchange.SignatureAlgorithm,
			state.PeerCertificates,
		); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
		}
		var chains [][]*x509.Certificate
		if !cfg.InsecureSkipVerify {
			certAlgs := cfg.LocalCertSignatureSchemes
			if len(certAlgs) == 0 {
				certAlgs = cfg.LocalSignatureSchemes
			}
			chains, err = dtlscrypto.VerifyServerCert(
				state.PeerCertificates, cfg.RootCAs, cfg.ServerName, certAlgs,
			)
			if err != nil {
				return &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
			}
		}
		if cfg.VerifyPeerCertificate != nil {
			if err = cfg.VerifyPeerCertificate(state.PeerCertificates, chains); err != nil {
				return &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
			}
		}
	}
	if cfg.VerifyConnection != nil {
		if verifyErr := cfg.VerifyConnection(state); verifyErr != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, verifyErr
		}
	}

	if err = state.InitCipherSuite(); err != nil {
		return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	cfg.WriteKeyLog(keyLogLabel, clientRandom[:], state.MasterSecret)

	return nil, nil //nolint
}
