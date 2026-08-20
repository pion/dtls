// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"context"
	"errors"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/internal/negotiation"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

//nolint:cyclop
func flight1Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	state := flightCtx.state
	cfg := flightCtx.cfg
	state.ResetConnectionIDs()
	state.SetSRTPProtectionProfile(0)
	state.LocalClientHelloSnapshots.Reset()

	state.SetLocalEpoch(EpochInitial)
	state.SetRemoteEpoch(EpochInitial)
	if len(cfg.EllipticCurves) == 0 {
		return nil, nil, dtlserrors.ErrEmptyEllipticCurves
	}
	if len(cfg.LocalSignatureSchemes) == 0 {
		return nil, nil, dtlserrors.ErrNoAvailableSignatureSchemes
	}
	state.SelectedGroup = cfg.EllipticCurves[0]
	state.Cookie = nil

	if err := state.LocalRandom.Populate(); err != nil {
		return nil, nil, err
	}

	if cfg.HelloRandomBytesGenerator != nil {
		state.LocalRandom.RandomBytes = cfg.HelloRandomBytesGenerator()
	}

	extensions := []extension.Value{
		&extension.SignatureAlgorithms{
			Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes),
		},
	}

	if cfg.ExtendedMasterSecret == dtlsconfig.RequestExtendedMasterSecret ||
		cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret {
		extensions = append(extensions, &extension12.ExtendedMasterSecret{})
	}

	extensions = append(extensions, &extension12.RenegotiationInfo{
		RenegotiatedConnection: 0,
	})

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
				Groups: cfg.EllipticCurves,
			},
			&extension12.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}...)
	}

	if len(cfg.SupportedProtocols) > 0 {
		extensions = append(extensions, &extension.ALPNOffer{Protocols: cfg.SupportedProtocols})
	}

	entries := make([]extension13.KeyShareEntry, 0, len(cfg.EllipticCurves))
	keypairs := make(map[elliptic.Curve]*elliptic.Keypair, len(cfg.EllipticCurves))
	for _, group := range cfg.EllipticCurves {
		keypair, err := elliptic.GenerateKeypair(group)
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, extension13.KeyShareEntry{
			Group: keypair.Curve, KeyExchange: keypair.PublicKey,
		})
		keypairs[keypair.Curve] = keypair
	}
	state.LocalKeyEntries = entries
	state.LocalKeypairs = keypairs
	extensions = append(extensions, &extension13.ClientKeyShare{
		Shares: entries,
	})

	extensions = append(extensions, &extension13.OfferedVersions{
		Versions: dtlsconfig.SupportedVersionsRange(cfg.MinVersion, cfg.MaxVersion),
	})

	if len(cfg.LocalCertSignatureSchemes) > 0 {
		extensions = append(extensions, &extension.CertificateSignatureAlgorithms{
			Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalCertSignatureSchemes),
		})
	}

	if len(cfg.ServerName) > 0 {
		extensions = append(extensions, &extension.ServerNameOffer{ServerName: cfg.ServerName})
	}

	if len(cfg.LocalSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &extension.SRTPOffer{
			ProtectionProfiles:  cfg.LocalSRTPProtectionProfiles,
			MasterKeyIdentifier: cfg.LocalSRTPMasterKeyIdentifier,
		})
	}

	if cfg.ConnectionIDGenerator != nil {
		extensions = append(extensions, &extension.ConnectionID{
			CID: bytes.Clone(cfg.ConnectionIDGenerator()),
		})
	}

	// Pre_shared_key must be last extension

	clientHello := &handshake.MessageClientHello{
		Version:   protocol.Version1_2,
		SessionID: state.SessionID,
		Cookie:    nil,
		Random:    state.LocalRandom,
		// Add DTLS 1.3 ciphersuites
		CipherSuiteIDs:     dtlsflight.CipherSuiteIDs(cfg.LocalCipherSuites),
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
		Extensions:         extensions,
	}

	clientHello, snapshot, err := negotiation.FinalizeClientHello(clientHello, cfg.ClientHelloMessageHook)
	if err != nil {
		return nil, nil, err
	}
	if err := state.RecordLocalClientHello(snapshot); err != nil {
		return nil, nil, err
	}
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

// nolint:cyclop
func flight1Parse(
	ctx context.Context,
	conn dtlsflight.Conn,
	flightCtx *handshakeContext,
) (Flight, *alert.Alert, error) {
	state := flightCtx.state
	cache := flightCtx.cache
	cfg := flightCtx.cfg

	if state.RemoteEpoch() >= EpochHandshake {
		// a direct ServerHello can leave the protected server flight pending,
		// so resume it instead of pulling ServerHello again.
		//
		// https://datatracker.ietf.org/doc/html/rfc9147#section-5.5
		return flight3Parse(ctx, conn, flightCtx)
	}

	pull := cache.FullPullMapItems(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false, Optional: false}, //nolint:lll
	)
	if pull.Err != nil {
		return 0, nil, pull.Err
	}
	if !pull.Ready {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	sh, ok := pull.Messages[handshake.TypeServerHello].(*handshake.MessageServerHello)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if !IsHelloRetryRequest(sh) {
		// Flight1 and flight2 were skipped.
		// Parse as flight3.
		return flight3Parse(ctx, conn, flightCtx)
	}
	// Handle HelloRetryRequest

	if !sh.Version.Equal(protocol.Version1_0) && !sh.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
			dtlserrors.ErrUnsupportedProtocolVersion
	}
	if err := validateHelloRetryRequestSelectedVersion(sh.Extensions); err != nil {
		description := alert.IllegalParameter
		switch {
		case errors.Is(err, dtlserrors.ErrUnsupportedProtocolVersion):
			description = alert.ProtocolVersion
		case errors.Is(err, dtlserrors.ErrMissingSupportedVersionsExtension):
			description = alert.MissingExtension
		}

		return 0, &alert.Alert{Level: alert.Fatal, Description: description}, err
	}
	if err := negotiation.ValidateServerHelloResponse(
		state.LocalClientHelloSnapshots.Current(), sh,
	); err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.UnsupportedExtension}, err
	}
	selectedCipherSuite, dtlsAlert, err := selectServerHelloCipherSuite(sh, cfg)
	if err != nil {
		return 0, dtlsAlert, err
	}
	state.CipherSuite = selectedCipherSuite

	// nolint:godox
	// TODO: negotiate minimial set of extensions necessary for the client
	// to generate a correct CH pair. As with the ServerHello, a
	// HelloRetryRequest MUST NOT contain any extensions that were not first
	// offered by the client in its ClientHello, with the exception of
	// optionally the "cookie" extension
	for _, val := range sh.Extensions {
		switch ext := val.(type) {
		case *extension13.SelectedVersion:
			// nolint:godox
			// TODO: negotiate version
			state.RemoteVersions = []protocol.Version{ext.Version}
		case *extension13.Cookie:
			state.Cookie = bytes.Clone(ext.Cookie)
		case *extension13.RetryKeyShare:
			state.RemoteKeyEntries = []extension13.KeyShareEntry{{Group: ext.SelectedGroup}}
			state.HasRemoteKeyEntries = true
		}
	}

	if flightCtx.inboundHandshakeHandler != nil {
		if err := flightCtx.inboundHandshakeHandler(state.CipherSuite, pull.Items); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}
	state.HandshakeRecvSequence = pull.NextSequence

	return Flight3, nil, nil
}
