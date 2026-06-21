// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// we'll add the flight handlers for the DTLS 1.3 client here.
//
// +----------+
// | Flight 1 |
// | Flight 3 |
// | Flight 5 |
// +----------+
//
// +-----------+
// | Flight 3a |
// | Flight 5a |
// +-----------+
//
// +-----------+
// | Flight 3b |
// | Flight 5b |
// +-----------+
//
// +-----------+
// | Flight 5c |
// +-----------+

// nolint:unused
func flight13_1Parse(
	ctx context.Context,
	conn flightConn,
	flightCtx *handshakeContext13,
) (flightVal13, *alert.Alert, error) {
	state := flightCtx.state
	cache := flightCtx.cache
	cfg := flightCtx.cfg

	seq, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence, state.cipherSuite,
		handshakeCachePullRule{handshake.TypeServerHello, cfg.initialEpoch, false, true},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	sh, ok := msgs[handshake.TypeServerHello].(*handshake.MessageServerHello)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	randomBytes := sh.Random.MarshalFixed()
	if !bytes.Equal(randomBytes[:], handshake.HelloRetryRequestRandom()) {
		// Flight1 and flight2 were skipped.
		// Parse as flight3.
		return flight13_3Parse(ctx, conn, flightCtx)
	}
	// Handle HelloRetryRequest

	if !sh.Version.Equal(protocol.Version1_0) && !sh.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, errUnsupportedProtocolVersion
	}

	// nolint:godox
	// TODO: negotiate minimial set of extensions necessary for the client
	// to generate a correct CH pair. As with the ServerHello, a
	// HelloRetryRequest MUST NOT contain any extensions that were not first
	// offered by the client in its ClientHello, with the exception of
	// optionally the "cookie" extension
	for _, val := range sh.Extensions {
		switch ext := val.(type) {
		case *extension.SupportedVersions:
			// nolint:godox
			// TODO: negotiate version
			state.remoteVersions = ext.Versions
		case *extension.CookieExt:
			state.cookie = ext.Cookie
		case *extension.KeyShare:
			state.remoteKeyEntries = ext.ClientShares
		}
	}

	state.handshakeRecvSequence = seq

	return flight13_3, nil, nil
}

//nolint:unused
func flight13_3Parse(
	ctx context.Context,
	conn flightConn,
	flightCtx *handshakeContext13,
) (flightVal13, *alert.Alert, error) {
	return 0, nil, errFlightUnimplemented13
}

//nolint:cyclop
func flight13_1Generate(
	_ flightConn,
	flightCtx *handshakeContext13,
) ([]*packet, *alert.Alert, error) {
	state := flightCtx.state
	cfg := flightCtx.cfg

	var zeroEpoch uint16
	state.localEpoch.Store(zeroEpoch)
	state.remoteEpoch.Store(zeroEpoch)
	if len(cfg.ellipticCurves) < 1 {
		return nil, nil, errEmptyEllipticCurves
	}
	state.namedCurve = cfg.ellipticCurves[0]
	state.cookie = nil

	if err := state.localRandom.Populate(); err != nil {
		return nil, nil, err
	}

	if cfg.helloRandomBytesGenerator != nil {
		state.localRandom.RandomBytes = cfg.helloRandomBytesGenerator()
	}

	extensions := []extension.Extension{}

	if cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		cfg.extendedMasterSecret == RequireExtendedMasterSecret {
		extensions = append(extensions, &extension.UseExtendedMasterSecret{
			Supported: true,
		})
	}

	extensions = append(extensions, &extension.RenegotiationInfo{
		RenegotiatedConnection: 0,
	})

	var setEllipticCurveCryptographyClientHelloExtensions bool
	for _, c := range cfg.localCipherSuites {
		if c.ECC() {
			setEllipticCurveCryptographyClientHelloExtensions = true

			break
		}
	}

	if setEllipticCurveCryptographyClientHelloExtensions {
		extensions = append(extensions, []extension.Extension{
			&extension.SupportedEllipticCurves{
				EllipticCurves: cfg.ellipticCurves,
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}...)
	}

	if len(cfg.supportedProtocols) > 0 {
		extensions = append(extensions, &extension.ALPN{ProtocolNameList: cfg.supportedProtocols})
	}

	var entries []extension.KeyShareEntry
	for _, group := range cfg.ellipticCurves {
		keypair, err := elliptic.GenerateKeypair(group)
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, extension.KeyShareEntry{
			Group: keypair.Curve, KeyExchange: keypair.PublicKey,
		})
	}
	state.localKeyEntries = entries
	extensions = append(extensions, &extension.KeyShare{
		ClientShares: entries,
	})

	extensions = append(extensions, &extension.SupportedVersions{
		Versions: supportedVersionsRange(cfg.minVersion, cfg.maxVersion),
	})

	if len(cfg.localCertSignatureSchemes) > 0 {
		extensions = append(extensions, &extension.SignatureAlgorithmsCert{
			SignatureHashAlgorithms: cfg.localCertSignatureSchemes,
		})
	}

	if len(cfg.serverName) > 0 {
		extensions = append(extensions, &extension.ServerName{ServerName: cfg.serverName})
	}

	if len(cfg.localSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &extension.UseSRTP{
			ProtectionProfiles:  cfg.localSRTPProtectionProfiles,
			MasterKeyIdentifier: cfg.localSRTPMasterKeyIdentifier,
		})
	}

	// connection ID

	// Pre_shared_key must be last extension

	clientHello := &handshake.MessageClientHello{
		Version:   protocol.Version1_2,
		SessionID: state.SessionID,
		Cookie:    nil,
		Random:    state.localRandom,
		// Add DTLS 1.3 ciphersuites
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
