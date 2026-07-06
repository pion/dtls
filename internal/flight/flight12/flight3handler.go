// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"bytes"
	"context"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
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
	conn dtlsflight.Conn,
	state *dtlsstate.State,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (Flight, *alert.Alert, error) {
	// Clients may receive multiple HelloVerifyRequest messages with different cookies.
	// Clients SHOULD handle this by sending a new ClientHello with a cookie in response
	// to the new HelloVerifyRequest. RFC 6347 Section 4.2.1
	seq, msgs, ok := cache.FullPullMap(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeHelloVerifyRequest, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true}, //nolint:lll
	)
	if ok {
		if h, msgOk := msgs[handshake.TypeHelloVerifyRequest].(*handshake.MessageHelloVerifyRequest); msgOk {
			// DTLS 1.2 clients must not assume that the server will use the protocol version
			// specified in HelloVerifyRequest message. RFC 6347 Section 4.2.1
			if !h.Version.Equal(protocol.Version1_0) && !h.Version.Equal(protocol.Version1_2) {
				return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlserrors.ErrUnsupportedProtocolVersion //nolint:lll
			}
			state.Cookie = append([]byte{}, h.Cookie...)
			state.HandshakeRecvSequence = seq

			return Flight3, nil, nil
		}
	}

	_, msgs, ok = cache.FullPullMap(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false}, //nolint:lll
	)
	if !ok {
		// Don't have enough messages. Keep reading
		return 0, nil, nil
	}

	if serverHelloMsg, msgOk := msgs[handshake.TypeServerHello].(*handshake.MessageServerHello); msgOk { //nolint:nestif
		if !serverHelloMsg.Version.Equal(protocol.Version1_2) {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
				dtlserrors.ErrUnsupportedProtocolVersion
		}
		for _, v := range serverHelloMsg.Extensions {
			switch ext := v.(type) {
			case *extension.UseSRTP:
				profile, found := dtlsflight.FindMatchingSRTPProfile(ext.ProtectionProfiles, cfg.LocalSRTPProtectionProfiles)
				if !found {
					return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlserrors.ErrClientNoMatchingSRTPProfile //nolint:lll
				}
				state.SetSRTPProtectionProfile(profile)
				state.RemoteSRTPMasterKeyIdentifier = ext.MasterKeyIdentifier
			case *extension.UseExtendedMasterSecret:
				if cfg.ExtendedMasterSecret != dtlsconfig.DisableExtendedMasterSecret {
					state.ExtendedMasterSecret = true
				}
			case *extension.ALPN:
				if len(ext.ProtocolNameList) > 1 { // This should be exactly 1, the zero case is handle when unmarshalling
					return 0, &alert.Alert{
						Level:       alert.Fatal,
						Description: alert.InternalError,
					}, extension.ErrALPNInvalidFormat // Meh, internal error?
				}
				state.NegotiatedProtocol = ext.ProtocolNameList[0]
			case *extension.ConnectionID:
				// Only set connection ID to be sent if client supports connection
				// IDs.
				if cfg.ConnectionIDGenerator != nil {
					state.RemoteConnectionID = ext.CID
				}
			}
		}
		// If the server doesn't support connection IDs, the client should not
		// expect one to be sent.
		if state.RemoteConnectionID == nil {
			state.SetLocalConnectionID(nil)
		}

		if cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret && !state.ExtendedMasterSecret {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrClientRequiredButNoServerEMS //nolint:lll
		}
		if len(cfg.LocalSRTPProtectionProfiles) > 0 && state.GetSRTPProtectionProfile() == 0 {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlserrors.ErrRequestedButNoSRTPExtension //nolint:lll
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
			return handleResumption(ctx, conn, state, cache, cfg)
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
			state.SessionID = serverHelloMsg.SessionID
		}

		state.MasterSecret = []byte{}
	}

	if cfg.LocalPSKCallback != nil {
		seq, msgs, ok = cache.FullPullMap(state.HandshakeRecvSequence+1, state.CipherSuite,
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerKeyExchange, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true}, //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHelloDone, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},  //nolint:lll
		)
	} else {
		seq, msgs, ok = cache.FullPullMap(state.HandshakeRecvSequence+1, state.CipherSuite,
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificate, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true},        //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerKeyExchange, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false}, //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificateRequest, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true}, //nolint:lll
			dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHelloDone, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false},   //nolint:lll
		)
	}
	if !ok {
		// Don't have enough messages. Keep reading
		return 0, nil, nil
	}
	state.HandshakeRecvSequence = seq

	if h, ok := msgs[handshake.TypeCertificate].(*handshake.MessageCertificate); ok {
		state.PeerCertificates = h.Certificate
	} else if state.CipherSuite.AuthenticationType() == ciphersuite.AuthenticationTypeCertificate {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.NoCertificate}, dtlserrors.ErrInvalidCertificate
	}

	if h, ok := msgs[handshake.TypeServerKeyExchange].(*handshake.MessageServerKeyExchange); ok {
		alertPtr, err := handleServerKeyExchange(conn, state, cfg, h)
		if err != nil {
			return 0, alertPtr, err
		}
	}

	if creq, ok := msgs[handshake.TypeCertificateRequest].(*handshake.MessageCertificateRequest); ok {
		state.RemoteCertRequestAlgs = creq.SignatureHashAlgorithms
		state.RemoteRequestedCertificate = true
	}

	return Flight5, nil, nil
}

func handleResumption(
	ctx context.Context,
	c dtlsflight.Conn,
	state *dtlsstate.State,
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

	_, msgs, ok := cache.FullPullMap(state.HandshakeRecvSequence+1, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeFinished, Epoch: cfg.InitialEpoch + 1, IsClient: false, Optional: false}, //nolint:lll
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	var finished *handshake.MessageFinished
	if finished, ok = msgs[handshake.TypeFinished].(*handshake.MessageFinished); !ok {
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
	state *dtlsstate.State,
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
		if psk, err = cfg.LocalPSKCallback(keyExchangeMessage.IdentityHint); err != nil {
			return &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
		state.IdentityHint = keyExchangeMessage.IdentityHint
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

func flight3Generate(
	_ dtlsflight.Conn,
	state *dtlsstate.State,
	_ *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	extensions := []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
		},
		&extension.RenegotiationInfo{
			RenegotiatedConnection: 0,
		},
	}

	if len(cfg.LocalCertSignatureSchemes) > 0 {
		extensions = append(extensions, &extension.SignatureAlgorithmsCert{
			SignatureHashAlgorithms: cfg.LocalCertSignatureSchemes,
		})
	}

	if state.NamedCurve != 0 {
		ellipticCurves := supportedEllipticCurves(cfg.EllipticCurves)

		extensions = append(extensions, []extension.Extension{
			&extension.SupportedEllipticCurves{
				EllipticCurves: ellipticCurves,
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}...)
	}

	if len(cfg.LocalSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &extension.UseSRTP{
			ProtectionProfiles:  cfg.LocalSRTPProtectionProfiles,
			MasterKeyIdentifier: cfg.LocalSRTPMasterKeyIdentifier,
		})
	}

	if cfg.ExtendedMasterSecret == dtlsconfig.RequestExtendedMasterSecret ||
		cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret {
		extensions = append(extensions, &extension.UseExtendedMasterSecret{
			Supported: true,
		})
	}

	if len(cfg.ServerName) > 0 {
		extensions = append(extensions, &extension.ServerName{ServerName: cfg.ServerName})
	}

	if len(cfg.SupportedProtocols) > 0 {
		extensions = append(extensions, &extension.ALPN{ProtocolNameList: cfg.SupportedProtocols})
	}

	// If we sent a connection ID on the first ClientHello, send it on the
	// second.
	if state.GetLocalConnectionID() != nil {
		extensions = append(extensions, &extension.ConnectionID{CID: state.GetLocalConnectionID()})
	}

	clientHello := &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		SessionID:          state.SessionID,
		Cookie:             state.Cookie,
		Random:             state.LocalRandom,
		CipherSuiteIDs:     dtlsflight.CipherSuiteIDs(cfg.LocalCipherSuites),
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
		Extensions:         extensions,
	}

	var content handshake.Handshake

	if cfg.ClientHelloMessageHook != nil {
		content = handshake.Handshake{Message: cfg.ClientHelloMessageHook(*clientHello)}
	} else {
		content = handshake.Handshake{Message: clientHello}
	}

	return []*dtlsflight.Packet{
		{
			Record: &recordlayer.RecordLayer{
				Header: recordlayer.Header{
					Version: protocol.Version1_2,
				},
				Content: &content,
			},
		},
	}, nil, nil
}
