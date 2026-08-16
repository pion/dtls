// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"bytes"
	"context"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/internal/extensionnegotiation"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func flight1Parse(
	ctx context.Context,
	conn dtlsflight.Conn,
	state *dtlsstate.State12,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (Flight, *alert.Alert, error) {
	// HelloVerifyRequest can be skipped by the server,
	// so allow ServerHello during flight1 also
	pull := cache.FullPullMapOneOfItems(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeHelloVerifyRequest, Epoch: cfg.InitialEpoch, IsClient: false}, //nolint:lll
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false},        //nolint:lll
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
		if !h.Version.Equal(protocol.Version1_0) && !h.Version.Equal(protocol.Version1_2) {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
				dtlserrors.ErrUnsupportedProtocolVersion
		}
		state.Cookie = bytes.Clone(h.Cookie)
		state.HandshakeRecvSequence = pull.NextSequence

		return Flight3, nil, nil
	}

	return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
}

//nolint:cyclop
func flight1Generate(
	conn dtlsflight.Conn,
	state *dtlsstate.State12,
	_ *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	state.LocalClientHelloSnapshots.Reset()

	var zeroEpoch uint16
	state.SetLocalEpoch(zeroEpoch)
	state.SetRemoteEpoch(zeroEpoch)
	ellipticCurves := supportedEllipticCurves(cfg.EllipticCurves)
	if len(ellipticCurves) == 0 {
		return nil, nil, dtlserrors.ErrEmptyEllipticCurves
	}
	state.NamedCurve = ellipticCurves[0]
	state.Cookie = nil

	if err := state.LocalRandom.Populate(); err != nil {
		return nil, nil, err
	}

	if cfg.HelloRandomBytesGenerator != nil {
		state.LocalRandom.RandomBytes = cfg.HelloRandomBytesGenerator()
	}

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

	var setEllipticCurveCryptographyClientHelloExtensions bool
	for _, c := range cfg.LocalCipherSuites {
		if c.ECC() {
			setEllipticCurveCryptographyClientHelloExtensions = true

			break
		}
	}

	if setEllipticCurveCryptographyClientHelloExtensions {
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

	if cfg.ExtendedMasterSecret == dtlsconfig.RequestExtendedMasterSecret ||
		cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret {
		extensions = append(extensions, &extension12.ExtendedMasterSecret{})
	}

	if len(cfg.ServerName) > 0 {
		extensions = append(extensions, &extension.ServerNameOffer{ServerName: cfg.ServerName})
	}

	if len(cfg.SupportedProtocols) > 0 {
		extensions = append(extensions, &extension.ALPNOffer{Protocols: cfg.SupportedProtocols})
	}

	if cfg.HasSessionStore {
		cfg.Log.Tracef("[handshake] try to resume session")
		if id, secret, err := cfg.GetSession(conn.SessionKey()); err != nil {
			return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		} else if id != nil {
			cfg.Log.Tracef("[handshake] get saved session: %x", id)

			state.SessionID = id
			state.MasterSecret = secret
		}
	}

	// If we have a connection ID generator, use it. The CID may be zero length,
	// in which case we are just requesting that the server send us a CID to
	// use.
	if cfg.ConnectionIDGenerator != nil {
		state.SetLocalConnectionID(cfg.ConnectionIDGenerator())
		state.LocalCIDOffered = true
		extensions = append(extensions, &extension.ConnectionID{CID: state.LocalConnectionID()})
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

	clientHello, snapshot, err := extensionnegotiation.FinalizeClientHello(clientHello, cfg.ClientHelloMessageHook)
	if err != nil {
		return nil, nil, err
	}
	state.LocalClientHelloSnapshots.Record(snapshot)
	content := handshake.Handshake{Message: clientHello}

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
