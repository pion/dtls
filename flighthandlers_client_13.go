// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
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
		Cookie:    state.cookie,
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
