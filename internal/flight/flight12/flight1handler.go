// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"bytes"
	"context"
	"slices"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls12"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

func flight1Parse(ctx context.Context, conn dtlsflight.Conn, state *dtlsstate.State12, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) (Flight, *alert.Alert, error) {
	// HelloVerifyRequest can be skipped by the server,
	// so allow ServerHello during flight1 also
	pull := cache.FullPullMapOneOfItems(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeHelloVerifyRequest, Epoch: cfg.InitialEpoch, IsClient: false},
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false},
	)
	if pull.Err != nil {
		return 0, nil, pull.Err
	}
	if !pull.Ready {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if _, ok := pull.Messages[handshake.TypeServerHello]; ok {
		// Flight1 and flight2 were skipped.
		// Parse as flight3.
		return flight3Parse(ctx, conn, state, cache, cfg)
	}

	if h, ok := pull.Messages[handshake.TypeHelloVerifyRequest].(*handshake.MessageHelloVerifyRequest); ok {
		// DTLS 1.2 clients must not assume that the server will use the protocol version
		// specified in HelloVerifyRequest message. RFC 6347 Section 4.2.1
		if h.Version != protocol.Version1_0 && h.Version != protocol.Version1_2 {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlserrors.ErrUnsupportedProtocolVersion
		}
		state.Cookie = bytes.Clone(h.Cookie)
		state.HasHelloVerifyRequest = true
		state.HandshakeRecvSequence = pull.NextSequence

		return Flight3, nil, nil
	}

	return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
}

func flight1Generate(conn dtlsflight.Conn, state *dtlsstate.State12, _ *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	// A new handshake must authenticate the peer and derive fresh record keys,
	// even when an earlier attempt on this connection timed out.
	state.Protection = nil
	state.LocalVerifyData = nil
	state.ResetConnectionIDs()
	state.SetSRTPProtectionProfile(0)
	state.LocalClientHelloSnapshots.Reset()

	var zeroEpoch uint64
	state.SetLocalEpoch(zeroEpoch)
	state.SetRemoteEpoch(zeroEpoch)
	ellipticCurves := supportedEllipticCurves(cfg.EllipticCurves)
	if len(ellipticCurves) == 0 {
		return nil, nil, dtlserrors.ErrEmptyEllipticCurves
	}
	state.NamedCurve = ellipticCurves[0]
	state.Cookie = nil
	state.HasHelloVerifyRequest = false

	if err := state.LocalRandom.Populate(); err != nil {
		return nil, nil, err
	}

	if cfg.HelloRandomBytesGenerator != nil {
		state.LocalRandom.RandomBytes = cfg.HelloRandomBytesGenerator()
	}

	extensions := clientHello12SignatureExtensions(cfg)
	if clientHelloHasECC(cfg) {
		extensions = append(extensions, &extension.SupportedGroups{Groups: ellipticCurves}, &extension12.SupportedPointFormats{PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed}})
	}
	extensions = appendClientHello12Negotiation(extensions, cfg)

	if cfg.HasSessionStore {
		cfg.Log.Tracef("[handshake] try to resume session")
		if session, err := cfg.GetSession(conn.SessionKey()); err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		} else if cfg.UsableSession(session, true) {
			cfg.Log.Tracef("[handshake] get saved session: %x", session.ID)

			state.ResumeSession = &session
			state.SessionID = session.ID
			state.MasterSecret = session.Secret
			state.IdentityHint = bytes.Clone(session.IdentityHint)
			state.PSKHash = session.PSKHash
			state.PeerCertificates = session.PeerCertificates
		}
	}

	// If we have a connection ID generator, use it. The CID may be zero length,
	// in which case we are just requesting that the server send us a CID to
	// use.
	if cfg.ConnectionIDGenerator != nil {
		cid, err := cfg.GenerateConnectionID()
		if err != nil {
			return nil, nil, err
		}
		extensions = dtlsflight.AppendConnectionIDExtensions(
			extensions, cid, cfg.EnableRRC,
		)
	}

	clientHello := &handshake.MessageClientHello{Version: protocol.Version1_2, SessionID: state.SessionID, Cookie: state.Cookie, Random: state.LocalRandom, CipherSuiteIDs: dtlsflight.CipherSuiteIDs(cfg.LocalCipherSuites), CompressionMethods: dtlsflight.DefaultCompressionMethods(), Extensions: extensions}

	return finalizeClientHello12(state, cfg, clientHello, false)
}

func finalizeClientHello12(state *dtlsstate.State12, cfg *dtlsconfig.HandshakeConfig, clientHello *handshake.MessageClientHello, retry bool) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	clientHello, snapshot, err := dtlsflight.FinalizeClientHello(clientHello, cfg)
	if err != nil {
		return nil, nil, err
	}
	if retry && state.HasHelloVerifyRequest {
		if err := negotiation.ValidateHelloVerifyRequestResponse(state.LocalClientHelloSnapshots.Initial(), snapshot, state.Cookie); err != nil {
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

func clientHello12SignatureExtensions(cfg *dtlsconfig.HandshakeConfig) []extension.Value {
	var extensions []extension.Value
	if len(cfg.LocalSignatureSchemes) > 0 {
		extensions = append(extensions, &extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes)})
	}
	extensions = append(extensions, &extension12.RenegotiationInfo{RenegotiatedConnection: 0})

	if len(cfg.LocalCertSignatureSchemes) > 0 {
		extensions = append(extensions, &extension.CertificateSignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalCertSignatureSchemes)})
	}

	return extensions
}

func appendClientHello12Negotiation(extensions []extension.Value, cfg *dtlsconfig.HandshakeConfig) []extension.Value {
	if len(cfg.LocalSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &extension.SRTPOffer{ProtectionProfiles: cfg.LocalSRTPProtectionProfiles, MasterKeyIdentifier: cfg.LocalSRTPMasterKeyIdentifier})
	}

	if isExtendedMasterSecretRequested(cfg.ExtendedMasterSecret) {
		extensions = append(extensions, &extension12.ExtendedMasterSecret{})
	}

	if cfg.SendServerName() {
		extensions = append(extensions, &extension.ServerNameOffer{ServerName: cfg.ServerName})
	}

	if len(cfg.SupportedProtocols) > 0 {
		extensions = append(extensions, &extension.ALPNOffer{Protocols: cfg.SupportedProtocols})
	}

	return extensions
}

func clientHelloHasECC(cfg *dtlsconfig.HandshakeConfig) bool {
	return slices.ContainsFunc(cfg.LocalCipherSuites, func(suite dtlsconfig.CipherSuite) bool { return suite.ECC() })
}
