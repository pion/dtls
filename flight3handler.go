// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"

	"github.com/pion/dtls/v3/internal/ciphersuite/types"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

//nolint:gocognit,gocyclo,maintidx,cyclop
func flight3Parse(
	ctx context.Context,
	conn flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *alert.Alert, error) {
	// Clients may receive multiple HelloVerifyRequest messages with different cookies.
	// Clients SHOULD handle this by sending a new ClientHello with a cookie in response
	// to the new HelloVerifyRequest. RFC 6347 Section 4.2.1
	seq, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence, state.cipherSuite,
		handshakeCachePullRule{handshake.TypeHelloVerifyRequest, cfg.initialEpoch, false, true},
	)
	if ok {
		if h, msgOk := msgs[handshake.TypeHelloVerifyRequest].(*handshake.MessageHelloVerifyRequest); msgOk {
			// DTLS 1.2 clients must not assume that the server will use the protocol version
			// specified in HelloVerifyRequest message. RFC 6347 Section 4.2.1
			if !h.Version.Equal(protocol.Version1_0) && !h.Version.Equal(protocol.Version1_2) {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, errUnsupportedProtocolVersion
			}
			state.cookie = append([]byte{}, h.Cookie...)
			state.handshakeRecvSequence = seq

			return flight3, nil, nil
		}
	}

	_, msgs, ok = cache.fullPullMap(state.handshakeRecvSequence, state.cipherSuite,
		handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, false},
	)
	if !ok {
		// Don't have enough messages. Keep reading
		return 0, nil, nil
	}

	if serverHelloMsg, msgOk := msgs[handshake.TypeServerHello].(*handshake.MessageServerHello); msgOk { //nolint:nestif
		if !serverHelloMsg.Version.Equal(protocol.Version1_2) {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, errUnsupportedProtocolVersion
		}
		for _, v := range serverHelloMsg.Extensions {
			switch ext := v.(type) {
			case *extension.UseSRTP:
				profile, found := findMatchingSRTPProfile(ext.ProtectionProfiles, cfg.localSRTPProtectionProfiles)
				if !found || (len(ext.MasterKeyIdentifier) > 0 &&
					!bytes.Equal(ext.MasterKeyIdentifier, cfg.localSRTPMasterKeyIdentifier)) {
					return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, errClientNoMatchingSRTPProfile
				}
				state.setSRTPProtectionProfile(profile)
				state.remoteSRTPMasterKeyIdentifier = ext.MasterKeyIdentifier
			case *extension.UseExtendedMasterSecret:
				if cfg.extendedMasterSecret != DisableExtendedMasterSecret {
					state.extendedMasterSecret = true
				}
			case *extension.ALPN:
				if len(ext.ProtocolNameList) != 1 {
					return 0, &alert.Alert{
						Level:       alert.Fatal,
						Description: alert.InternalError,
					}, extension.ErrALPNInvalidFormat // Meh, internal error?
				}
				if err := validateServerSelectedALPN(cache, cfg.initialEpoch, ext.ProtocolNameList[0]); err != nil {
					return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
				}
				state.NegotiatedProtocol = ext.ProtocolNameList[0]
			case *extension.ConnectionID:
				// Only set connection ID to be sent if client supports connection
				// IDs.
				if cfg.connectionIDGenerator != nil {
					state.remoteConnectionID = ext.CID
				}
			}
		}
		// If the server doesn't support connection IDs, the client should not
		// expect one to be sent.
		if state.remoteConnectionID == nil {
			state.setLocalConnectionID(nil)
		}

		if cfg.extendedMasterSecret == RequireExtendedMasterSecret && !state.extendedMasterSecret {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errClientRequiredButNoServerEMS
		}
		if len(cfg.localSRTPProtectionProfiles) > 0 && state.getSRTPProtectionProfile() == 0 {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errRequestedButNoSRTPExtension
		}

		remoteCipherSuite := cipherSuiteForID(CipherSuiteID(*serverHelloMsg.CipherSuiteID), cfg.customCipherSuites)
		if remoteCipherSuite == nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errCipherSuiteNoIntersection
		}

		selectedCipherSuite, found := findMatchingCipherSuite([]CipherSuite{remoteCipherSuite}, cfg.localCipherSuites)
		if !found {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errInvalidCipherSuite
		}

		state.cipherSuite = selectedCipherSuite
		state.remoteRandom = serverHelloMsg.Random
		cfg.log.Tracef("[handshake] use cipher suite: %s", selectedCipherSuite.String())

		// Only the session offered in ClientHello can be resumed. A full
		// handshake's ServerHello may be parsed again while its flight arrives.
		if state.resumeSession != nil && bytes.Equal(state.resumeSession.ID, serverHelloMsg.SessionID) {
			if state.resumeSession.CipherSuiteID != state.cipherSuite.ID() {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, errInvalidCipherSuite
			}
			if state.resumeSession.ExtendedMasterSecret != state.extendedMasterSecret {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, errSessionEMSMismatch
			}

			return handleResumption(ctx, conn, state, cache, cfg)
		}

		if state.resumeSession != nil {
			cfg.log.Tracef("[handshake] clean old session : %s", state.SessionID)
			if err := cfg.sessionStore.Del(conn.sessionKey()); err != nil {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
			state.resumeSession = nil
			state.PeerCertificates = nil
			state.IdentityHint = nil
		}

		if cfg.sessionStore == nil {
			state.SessionID = []byte{}
		} else {
			state.SessionID = serverHelloMsg.SessionID
		}

		state.masterSecret = []byte{}
	}

	if cfg.localPSKCallback != nil {
		seq, msgs, ok = cache.fullPullMap(state.handshakeRecvSequence+1, state.cipherSuite,
			handshakeCachePullRule{handshake.TypeServerKeyExchange, cfg.initialEpoch, false, true},
			handshakeCachePullRule{handshake.TypeServerHelloDone, cfg.initialEpoch, false, false},
		)
	} else {
		seq, msgs, ok = cache.fullPullMap(state.handshakeRecvSequence+1, state.cipherSuite,
			handshakeCachePullRule{handshake.TypeCertificate, cfg.initialEpoch, false, true},
			handshakeCachePullRule{handshake.TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{handshake.TypeCertificateRequest, cfg.initialEpoch, false, true},
			handshakeCachePullRule{handshake.TypeServerHelloDone, cfg.initialEpoch, false, false},
		)
	}
	if !ok {
		// Don't have enough messages. Keep reading
		return 0, nil, nil
	}
	state.handshakeRecvSequence = seq

	if h, ok := msgs[handshake.TypeCertificate].(*handshake.MessageCertificate); ok {
		state.PeerCertificates = h.Certificate
	} else if state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, errInvalidCertificate
	}

	if h, ok := msgs[handshake.TypeServerKeyExchange].(*handshake.MessageServerKeyExchange); ok {
		alertPtr, err := handleServerKeyExchange(cache, state, cfg, h)
		if err != nil {
			return 0, alertPtr, err
		}
	}

	if creq, ok := msgs[handshake.TypeCertificateRequest].(*handshake.MessageCertificateRequest); ok {
		state.remoteCertRequestAlgs = creq.SignatureHashAlgorithms
		state.remoteRequestedCertificate = true
	}

	return flight5, nil, nil
}

func handleResumption(
	ctx context.Context,
	c flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *alert.Alert, error) {
	if err := state.initCipherSuite(); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	// Now, encrypted packets can be handled
	if err := c.handleQueuedPackets(ctx); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}

	_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence+1, state.cipherSuite,
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
	)

	expectedVerifyData, err := prf.VerifyDataServer(state.masterSecret, plainText, state.cipherSuite.HashFunc())
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if !bytes.Equal(expectedVerifyData, finished.VerifyData) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, errVerifyDataMismatch
	}
	if err := verifyResumedConnection(state, cfg); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.BadCertificate}, err
	}

	clientRandom := state.localRandom.MarshalFixed()
	cfg.writeKeyLog(keyLogLabelTLS12, clientRandom[:], state.masterSecret)

	return flight5b, nil, nil
}

//nolint:cyclop
func handleServerKeyExchange(
	cache *handshakeCache,
	state *State,
	cfg *handshakeConfig,
	keyExchangeMessage *handshake.MessageServerKeyExchange,
) (*alert.Alert, error) {
	var err error
	if state.cipherSuite == nil {
		return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errInvalidCipherSuite
	}
	if state.cipherSuite.KeyExchangeAlgorithm().Has(types.KeyExchangeAlgorithmEcdhe) {
		if err = validateServerSelectedCurve(cache, cfg.initialEpoch, keyExchangeMessage.NamedCurve); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, err
		}
	}
	if cfg.localPSKCallback != nil { //nolint:nestif
		var psk []byte
		if psk, err = cfg.localPSKCallback(keyExchangeMessage.IdentityHint); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		state.IdentityHint = keyExchangeMessage.IdentityHint
		state.pskHash = sha256.Sum256(psk)
		switch state.cipherSuite.KeyExchangeAlgorithm() {
		case types.KeyExchangeAlgorithmPsk:
			state.preMasterSecret = prf.PSKPreMasterSecret(psk)
		case (types.KeyExchangeAlgorithmEcdhe | types.KeyExchangeAlgorithmPsk):
			if state.localKeypair, err = elliptic.GenerateKeypair(keyExchangeMessage.NamedCurve); err != nil {
				return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
			state.preMasterSecret, err = prf.EcdhePSKPreMasterSecret(
				psk,
				keyExchangeMessage.PublicKey,
				state.localKeypair.PrivateKey,
				state.localKeypair.Curve,
			)
			if err != nil {
				return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
			}
		default:
			return &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errInvalidCipherSuite
		}
	} else {
		if state.localKeypair, err = elliptic.GenerateKeypair(keyExchangeMessage.NamedCurve); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}

		if state.preMasterSecret, err = prf.PreMasterSecret(
			keyExchangeMessage.PublicKey,
			state.localKeypair.PrivateKey,
			state.localKeypair.Curve,
		); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	return nil, nil //nolint:nilnil
}

func validateServerSelectedCurve(cache *handshakeCache, epoch uint16, curve elliptic.Curve) error {
	hello, err := cachedClientHello(cache, epoch)
	if err != nil {
		return err
	}
	for _, ext := range hello.Extensions {
		if groups, ok := ext.(*extension.SupportedEllipticCurves); ok && !slices.Contains(groups.EllipticCurves, curve) {
			return errServerSelectedUnofferedCurve
		}
	}

	return nil
}

func flight3Generate(
	_ flightConn,
	state *State,
	_ *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *alert.Alert, error) {
	extensions := []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.localSignatureSchemes,
		},
		&extension.RenegotiationInfo{
			RenegotiatedConnection: 0,
		},
	}

	if len(cfg.localCertSignatureSchemes) > 0 {
		extensions = append(extensions, &extension.SignatureAlgorithmsCert{
			SignatureHashAlgorithms: cfg.localCertSignatureSchemes,
		})
	}

	// Match flight1Generate: plain PSK must not add curve extensions on retry.
	if slices.ContainsFunc(cfg.localCipherSuites, func(suite CipherSuite) bool { return suite.ECC() }) {
		extensions = append(extensions, []extension.Extension{
			&extension.SupportedEllipticCurves{
				EllipticCurves: cfg.ellipticCurves,
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}...)
	}

	if len(cfg.localSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &extension.UseSRTP{
			ProtectionProfiles:  cfg.localSRTPProtectionProfiles,
			MasterKeyIdentifier: cfg.localSRTPMasterKeyIdentifier,
		})
	}

	if cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		cfg.extendedMasterSecret == RequireExtendedMasterSecret {
		extensions = append(extensions, &extension.UseExtendedMasterSecret{
			Supported: true,
		})
	}

	if shouldSendServerName(cfg.serverName) {
		extensions = append(extensions, &extension.ServerName{ServerName: cfg.serverName})
	}

	if len(cfg.supportedProtocols) > 0 {
		extensions = append(extensions, &extension.ALPN{ProtocolNameList: cfg.supportedProtocols})
	}

	// If we sent a connection ID on the first ClientHello, send it on the
	// second.
	if state.getLocalConnectionID() != nil {
		extensions = append(extensions, &extension.ConnectionID{CID: state.getLocalConnectionID()})
	}

	clientHello := &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		SessionID:          state.SessionID,
		Cookie:             state.cookie,
		Random:             state.localRandom,
		CipherSuiteIDs:     cipherSuiteIDs(cfg.localCipherSuites),
		CompressionMethods: defaultCompressionMethods(),
		Extensions:         extensions,
	}

	var content handshake.Handshake

	if cfg.clientHelloMessageHook != nil {
		content = handshake.Handshake{Message: cfg.clientHelloMessageHook(*clientHello)}
	} else {
		content = handshake.Handshake{Message: clientHello}
	}

	return []*packet{
		{
			record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &content,
			},
		},
	}, nil, nil
}

func cachedClientHello(cache *handshakeCache, epoch uint16) (*handshake.MessageClientHello, error) {
	// Use the latest ClientHello's wire bytes, including hook changes and retries.
	items := cache.pull(handshakeCachePullRule{handshake.TypeClientHello, epoch, true, false})
	if items[0] == nil {
		return nil, errLengthMismatch
	}
	message := &handshake.Handshake{}
	if err := message.Unmarshal(items[0].data); err != nil {
		return nil, err
	}
	hello, ok := message.Message.(*handshake.MessageClientHello)
	if !ok {
		return nil, errLengthMismatch
	}

	return hello, nil
}

func validateServerSelectedALPN(cache *handshakeCache, epoch uint16, selected string) error {
	hello, err := cachedClientHello(cache, epoch)
	if err != nil {
		return err
	}
	for _, ext := range hello.Extensions {
		if alpn, ok := ext.(*extension.ALPN); ok && slices.Contains(alpn.ProtocolNameList, selected) {
			return nil
		}
	}

	return extension.ErrALPNInvalidFormat
}
