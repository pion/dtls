// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"context"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func flight1Parse(
	ctx context.Context,
	conn dtlsflight.Conn,
	state *dtlsstate.State,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) (Flight, *alert.Alert, error) {
	// HelloVerifyRequest can be skipped by the server,
	// so allow ServerHello during flight1 also
	seq, msgs, ok := cache.FullPullMap(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeHelloVerifyRequest, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true}, //nolint:lll
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true},        //nolint:lll
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if _, ok := msgs[handshake.TypeServerHello]; ok {
		// Flight1 and flight2 were skipped.
		// Parse as flight3.
		return flight3Parse(ctx, conn, state, cache, cfg)
	}

	if h, ok := msgs[handshake.TypeHelloVerifyRequest].(*handshake.MessageHelloVerifyRequest); ok {
		// DTLS 1.2 clients must not assume that the server will use the protocol version
		// specified in HelloVerifyRequest message. RFC 6347 Section 4.2.1
		if !h.Version.Equal(protocol.Version1_0) && !h.Version.Equal(protocol.Version1_2) {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
				dtlserrors.ErrUnsupportedProtocolVersion
		}
		state.Cookie = append([]byte{}, h.Cookie...)
		state.HandshakeRecvSequence = seq

		return Flight3, nil, nil
	}

	return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
}

//nolint:cyclop
func flight1Generate(
	conn dtlsflight.Conn,
	state *dtlsstate.State,
	_ *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	var zeroEpoch uint16
	state.LocalEpoch.Store(zeroEpoch)
	state.RemoteEpoch.Store(zeroEpoch)
	ellipticCurves := supportedEllipticCurves(cfg.EllipticCurves)
	if len(ellipticCurves) < 1 {
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

	var setEllipticCurveCryptographyClientHelloExtensions bool
	for _, c := range cfg.LocalCipherSuites {
		if c.ECC() {
			setEllipticCurveCryptographyClientHelloExtensions = true

			break
		}
	}

	if setEllipticCurveCryptographyClientHelloExtensions {
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
		// The presence of a generator indicates support for connection IDs. We
		// use the presence of a non-nil local CID in flight 3 to determine
		// whether we send a CID in the second ClientHello, so we convert any
		// nil CID returned by a generator to []byte{}.
		if state.GetLocalConnectionID() == nil {
			state.SetLocalConnectionID([]byte{})
		}
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
