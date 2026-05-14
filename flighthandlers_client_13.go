// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"errors"
	"slices"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
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

func isHelloRetryRequest(sh *handshake.MessageServerHello) bool {
	randomBytes := sh.Random.MarshalFixed()

	return bytes.Equal(randomBytes[:], handshake.HelloRetryRequestRandom())
}

func serverHelloSelectedVersions(extensions []extension.Extension) ([]protocol.Version, bool, error) {
	seenSupportedVersions := false
	var versions []protocol.Version
	for _, val := range extensions {
		supportedVersions, ok := val.(*extension.SupportedVersions)
		if !ok {
			continue
		}
		if seenSupportedVersions || !supportedVersions.IsSelectedVersion() || len(supportedVersions.Versions) != 1 {
			return nil, true, errInvalidServerHello
		}
		seenSupportedVersions = true
		versions = supportedVersions.Versions
	}

	return versions, seenSupportedVersions, nil
}

func validateHelloRetryRequestSelectedVersion(extensions []extension.Extension) error {
	versions, seenSupportedVersions, err := serverHelloSelectedVersions(extensions)
	if err != nil || !seenSupportedVersions {
		return errInvalidHelloRetryRequest
	}
	if !versions[0].Equal(protocol.Version1_3) {
		return errUnsupportedProtocolVersion
	}

	return nil
}

// nolint:unused,cyclop
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

	if !isHelloRetryRequest(sh) {
		// Flight1 and flight2 were skipped.
		// Parse as flight3.
		return flight13_3Parse(ctx, conn, flightCtx)
	}
	// Handle HelloRetryRequest

	if !sh.Version.Equal(protocol.Version1_0) && !sh.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, errUnsupportedProtocolVersion
	}
	if err := validateHelloRetryRequestSelectedVersion(sh.Extensions); err != nil {
		description := alert.IllegalParameter
		if errors.Is(err, errUnsupportedProtocolVersion) {
			description = alert.ProtocolVersion
		}

		return 0, &alert.Alert{Level: alert.Fatal, Description: description}, err
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
			if ext.SelectedGroup != nil {
				state.remoteKeyEntries = &[]extension.KeyShareEntry{
					{Group: *ext.SelectedGroup},
				}
			}
		}
	}

	state.handshakeRecvSequence = seq

	return flight13_3, nil, nil
}

//nolint:cyclop
func flight13_3Parse(
	_ context.Context,
	_ flightConn,
	flightCtx *handshakeContext13,
) (flightVal13, *alert.Alert, error) {
	seq, msgs, ok := flightCtx.cache.fullPullMap(flightCtx.state.handshakeRecvSequence, flightCtx.state.cipherSuite,
		handshakeCachePullRule{handshake.TypeServerHello, flightCtx.cfg.initialEpoch, false, false},
	)
	if !ok {
		return 0, nil, nil
	}

	serverHello, ok := msgs[handshake.TypeServerHello].(*handshake.MessageServerHello)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if isHelloRetryRequest(serverHello) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage},
			errUnexpectedSecondHelloRetryRequest
	}

	if !serverHello.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, errUnsupportedProtocolVersion
	}

	versions, seenSupportedVersions, err := serverHelloSelectedVersions(serverHello.Extensions)
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, errInvalidServerHello
	}
	if !seenSupportedVersions || !versions[0].Equal(protocol.Version1_3) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, errUnsupportedProtocolVersion
	}
	flightCtx.state.remoteVersions = versions
	flightCtx.state.localVersion = protocol.Version1_3

	if serverHello.CipherSuiteID == nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, errInvalidServerHello
	}
	remoteCipherSuite := cipherSuiteForID(CipherSuiteID(*serverHello.CipherSuiteID), flightCtx.cfg.customCipherSuites)
	if remoteCipherSuite == nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errCipherSuiteNoIntersection
	}
	if !cipherSuiteIDSupportsVersion(remoteCipherSuite.ID(), protocol.Version1_3) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errInvalidCipherSuite
	}
	selectedCipherSuite, found := findMatchingCipherSuite(
		[]CipherSuite{remoteCipherSuite}, flightCtx.cfg.localCipherSuites,
	)
	if !found {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, errInvalidCipherSuite
	}
	flightCtx.state.cipherSuite = selectedCipherSuite
	flightCtx.state.remoteRandom = serverHello.Random
	flightCtx.cfg.log.Tracef("[handshake13] use cipher suite: %s", selectedCipherSuite.String())

	var serverShare *extension.KeyShareEntry
	for _, ext := range serverHello.Extensions {
		keyShare, isKeyShare := ext.(*extension.KeyShare)
		if isKeyShare && keyShare.ServerShare != nil {
			serverShare = keyShare.ServerShare

			break
		}
	}
	if serverShare == nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, errServerKeyShareMissing
	}

	localKeypair, ok := flightCtx.state.localKeypairs[serverShare.Group]
	if !ok || localKeypair == nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, errServerKeyShareUnknownGroup
	}

	preMasterSecret, err := prf.PreMasterSecret(serverShare.KeyExchange, localKeypair.PrivateKey, serverShare.Group)
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	flightCtx.state.preMasterSecret = preMasterSecret
	flightCtx.state.namedCurve = serverShare.Group
	flightCtx.state.remoteKeyEntries = &[]extension.KeyShareEntry{*serverShare}

	flightCtx.state.handshakeRecvSequence = seq

	return flight13_5, nil, nil
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

	entries := make([]extension.KeyShareEntry, 0, len(cfg.ellipticCurves))
	keypairs := make(map[elliptic.Curve]*elliptic.Keypair, len(cfg.ellipticCurves))
	for _, group := range cfg.ellipticCurves {
		keypair, err := elliptic.GenerateKeypair(group)
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, extension.KeyShareEntry{
			Group: keypair.Curve, KeyExchange: keypair.PublicKey,
		})
		keypairs[keypair.Curve] = keypair
	}
	state.localKeyEntries = entries
	state.localKeypairs = keypairs
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

// nolint:cyclop
func flight13_3Generate(
	_ flightConn,
	flightCtx *handshakeContext13,
) ([]*packet, *alert.Alert, error) {
	extensions := []extension.Extension{}

	if flightCtx.cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		flightCtx.cfg.extendedMasterSecret == RequireExtendedMasterSecret {
		extensions = append(extensions, &extension.UseExtendedMasterSecret{
			Supported: true,
		})
	}

	extensions = append(extensions, &extension.RenegotiationInfo{
		RenegotiatedConnection: 0,
	})

	if flightCtx.state.namedCurve != 0 {
		extensions = append(extensions, []extension.Extension{
			&extension.SupportedEllipticCurves{
				EllipticCurves: flightCtx.cfg.ellipticCurves,
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}...)
	}

	if len(flightCtx.cfg.supportedProtocols) > 0 {
		extensions = append(extensions, &extension.ALPN{ProtocolNameList: flightCtx.cfg.supportedProtocols})
	}

	var localGroups []elliptic.Curve
	var newEntries []extension.KeyShareEntry
	newKeypairs := map[elliptic.Curve]*elliptic.Keypair{}
	if flightCtx.state.remoteKeyEntries != nil {
		for _, entry := range flightCtx.state.localKeyEntries {
			localGroups = append(localGroups, entry.Group)
		}

		for _, entry := range *flightCtx.state.remoteKeyEntries {
			if !slices.Contains(localGroups, entry.Group) && slices.Contains(flightCtx.cfg.ellipticCurves, entry.Group) {
				keypair, err := elliptic.GenerateKeypair(entry.Group)
				if err != nil {
					return nil, nil, err
				}
				newEntries = append(newEntries, extension.KeyShareEntry{
					Group: keypair.Curve, KeyExchange: keypair.PublicKey,
				})
				newKeypairs[keypair.Curve] = keypair
			}
		}
	}
	if len(newEntries) > 0 {
		flightCtx.state.localKeyEntries = append(newEntries, flightCtx.state.localKeyEntries...)
		if flightCtx.state.localKeypairs == nil {
			flightCtx.state.localKeypairs = make(map[elliptic.Curve]*elliptic.Keypair, len(newKeypairs))
		}
		for group, keypair := range newKeypairs {
			flightCtx.state.localKeypairs[group] = keypair
		}
	}
	extensions = append(extensions, &extension.KeyShare{
		ClientShares: flightCtx.state.localKeyEntries,
	})

	if !slices.Contains(flightCtx.state.remoteVersions, protocol.Version1_3) {
		return nil, nil, errNoCommonProtocolVersion
	}
	extensions = append(extensions, &extension.SupportedVersions{
		Versions: supportedVersionsRange(flightCtx.cfg.minVersion, flightCtx.cfg.maxVersion),
	})

	if len(flightCtx.cfg.localCertSignatureSchemes) > 0 {
		extensions = append(extensions, &extension.SignatureAlgorithmsCert{
			SignatureHashAlgorithms: flightCtx.cfg.localCertSignatureSchemes,
		})
	}

	if len(flightCtx.cfg.serverName) > 0 {
		extensions = append(extensions, &extension.ServerName{ServerName: flightCtx.cfg.serverName})
	}

	if len(flightCtx.cfg.localSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &extension.UseSRTP{
			ProtectionProfiles:  flightCtx.cfg.localSRTPProtectionProfiles,
			MasterKeyIdentifier: flightCtx.cfg.localSRTPMasterKeyIdentifier,
		})
	}

	if len(flightCtx.state.cookie) > 0 {
		extensions = append(extensions, &extension.CookieExt{Cookie: flightCtx.state.cookie})
	}

	clientHello := &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		SessionID:          flightCtx.state.SessionID,
		Cookie:             []byte{},
		Random:             flightCtx.state.localRandom,
		CipherSuiteIDs:     cipherSuiteIDs(flightCtx.cfg.localCipherSuites),
		CompressionMethods: defaultCompressionMethods(),
		Extensions:         extensions,
	}

	var content handshake.Handshake

	if flightCtx.cfg.clientHelloMessageHook != nil {
		content = handshake.Handshake{Message: flightCtx.cfg.clientHelloMessageHook(*clientHello)}
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
