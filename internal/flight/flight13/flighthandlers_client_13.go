// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
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

func IsHelloRetryRequest(sh *handshake.MessageServerHello) bool {
	randomBytes := sh.Random.MarshalFixed()

	return bytes.Equal(randomBytes[:], handshake.HelloRetryRequestRandom())
}

func ServerHelloSelectedVersions(extensions []extension.Extension) ([]protocol.Version, bool, error) {
	seenSupportedVersions := false
	var versions []protocol.Version
	for _, val := range extensions {
		supportedVersions, ok := val.(*extension.SupportedVersions)
		if !ok {
			continue
		}
		if seenSupportedVersions || !supportedVersions.IsSelectedVersion() || len(supportedVersions.Versions) != 1 {
			return nil, true, dtlserrors.ErrInvalidServerHello
		}
		seenSupportedVersions = true
		versions = supportedVersions.Versions
	}

	return versions, seenSupportedVersions, nil
}

func validateHelloRetryRequestSelectedVersion(extensions []extension.Extension) error {
	versions, seenSupportedVersions, err := ServerHelloSelectedVersions(extensions)
	if err != nil || !seenSupportedVersions {
		return dtlserrors.ErrInvalidHelloRetryRequest
	}
	if !versions[0].Equal(protocol.Version1_3) {
		return dtlserrors.ErrUnsupportedProtocolVersion
	}

	return nil
}

func selectServerHelloCipherSuite13(
	serverHello *handshake.MessageServerHello,
	cfg *dtlsconfig.HandshakeConfig,
) (dtlsconfig.CipherSuite, *alert.Alert, error) {
	if serverHello.CipherSuiteID == nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
			dtlserrors.ErrInvalidServerHello
	}
	remoteCipherSuite := ciphersuite.ForID(ciphersuite.ID(*serverHello.CipherSuiteID), cfg.CustomCipherSuites)
	if remoteCipherSuite == nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity},
			dtlserrors.ErrCipherSuiteNoIntersection
	}
	if !ciphersuite.IDSupportsVersion(remoteCipherSuite.ID(), protocol.Version1_3) {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity},
			dtlserrors.ErrInvalidCipherSuite
	}
	selectedCipherSuite, found := dtlsflight.FindMatchingCipherSuite(
		[]dtlsconfig.CipherSuite{remoteCipherSuite}, cfg.LocalCipherSuites,
	)
	if !found {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity},
			dtlserrors.ErrInvalidCipherSuite
	}

	return selectedCipherSuite, nil, nil
}

// nolint:unused,cyclop
func flight13_1Parse(
	ctx context.Context,
	conn dtlsflight.Conn,
	flightCtx *handshakeContext13,
) (Flight, *alert.Alert, error) {
	state := flightCtx.state
	cache := flightCtx.cache
	cfg := flightCtx.cfg

	seq, msgs, items, ok := cache.FullPullMapItems(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: cfg.InitialEpoch, IsClient: false, Optional: true}, //nolint:lll
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	sh, ok := msgs[handshake.TypeServerHello].(*handshake.MessageServerHello)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if !IsHelloRetryRequest(sh) {
		// Flight1 and flight2 were skipped.
		// Parse as flight3.
		return flight13_3Parse(ctx, conn, flightCtx)
	}
	// Handle HelloRetryRequest

	if !sh.Version.Equal(protocol.Version1_0) && !sh.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
			dtlserrors.ErrUnsupportedProtocolVersion
	}
	if err := validateHelloRetryRequestSelectedVersion(sh.Extensions); err != nil {
		description := alert.IllegalParameter
		if errors.Is(err, dtlserrors.ErrUnsupportedProtocolVersion) {
			description = alert.ProtocolVersion
		}

		return 0, &alert.Alert{Level: alert.Fatal, Description: description}, err
	}
	selectedCipherSuite, dtlsAlert, err := selectServerHelloCipherSuite13(sh, cfg)
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
		case *extension.SupportedVersions:
			// nolint:godox
			// TODO: negotiate version
			state.RemoteVersions = ext.Versions
		case *extension.CookieExt:
			state.Cookie = ext.Cookie
		case *extension.KeyShare:
			if ext.SelectedGroup != nil {
				state.RemoteKeyEntries = &[]extension.KeyShareEntry{
					{Group: *ext.SelectedGroup},
				}
			}
		}
	}

	if flightCtx.inboundHandshakeHandler != nil {
		if err := flightCtx.inboundHandshakeHandler(state.CipherSuite, items); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}
	state.HandshakeRecvSequence = seq

	return Flight3, nil, nil
}

//nolint:cyclop
func flight13_3Parse(
	_ context.Context,
	_ dtlsflight.Conn,
	flightCtx *handshakeContext13,
) (Flight, *alert.Alert, error) {
	serverHelloSeq, msgs, items, ok := flightCtx.cache.FullPullMapItems(
		flightCtx.state.HandshakeRecvSequence, flightCtx.state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: flightCtx.cfg.InitialEpoch, IsClient: false, Optional: false}, //nolint:lll
	)
	if !ok {
		return 0, nil, nil
	}

	serverHello, ok := msgs[handshake.TypeServerHello].(*handshake.MessageServerHello)
	if !ok {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}

	if IsHelloRetryRequest(serverHello) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage},
			dtlserrors.ErrUnexpectedSecondHelloRetryRequest
	}

	if !serverHello.Version.Equal(protocol.Version1_2) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
			dtlserrors.ErrUnsupportedProtocolVersion
	}

	versions, seenSupportedVersions, err := ServerHelloSelectedVersions(serverHello.Extensions)
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlserrors.ErrInvalidServerHello
	}
	if !seenSupportedVersions || !versions[0].Equal(protocol.Version1_3) {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion},
			dtlserrors.ErrUnsupportedProtocolVersion
	}
	flightCtx.state.RemoteVersions = versions
	flightCtx.state.LocalVersion = protocol.Version1_3

	selectedCipherSuite, dtlsAlert, err := selectServerHelloCipherSuite13(serverHello, flightCtx.cfg)
	if err != nil {
		return 0, dtlsAlert, err
	}
	flightCtx.state.CipherSuite = selectedCipherSuite
	flightCtx.state.RemoteRandom = serverHello.Random
	flightCtx.cfg.Log.Tracef("[handshake13] use cipher suite: %s", selectedCipherSuite.String())

	var serverShare *extension.KeyShareEntry
	for _, ext := range serverHello.Extensions {
		keyShare, isKeyShare := ext.(*extension.KeyShare)
		if isKeyShare && keyShare.ServerShare != nil {
			serverShare = keyShare.ServerShare

			break
		}
	}
	if serverShare == nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlserrors.ErrServerKeyShareMissing
	}

	localKeypair, ok := flightCtx.state.LocalKeypairs[serverShare.Group]
	if !ok || localKeypair == nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
			dtlserrors.ErrServerKeyShareUnknownGroup
	}

	preMasterSecret, err := prf.PreMasterSecret(serverShare.KeyExchange, localKeypair.PrivateKey, serverShare.Group)
	if err != nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	flightCtx.state.PreMasterSecret = preMasterSecret
	flightCtx.state.NamedCurve = serverShare.Group
	flightCtx.state.RemoteKeyEntries = &[]extension.KeyShareEntry{*serverShare}

	if flightCtx.inboundHandshakeHandler != nil {
		if err := flightCtx.inboundHandshakeHandler(flightCtx.state.CipherSuite, items); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}
	if flightCtx.handshakeTrafficSecretDeriver != nil {
		if err := flightCtx.handshakeTrafficSecretDeriver(flightCtx.state); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}
	if flightCtx.handshakeRecordProtectionInitializer != nil {
		if err := flightCtx.handshakeRecordProtectionInitializer(flightCtx.state); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}

	seq, msgs, items, ok := flightCtx.cache.FullPullMapItems(
		serverHelloSeq, flightCtx.state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeEncryptedExtensions, Epoch: flightCtx.cfg.InitialEpoch + 1, IsClient: false, Optional: false}, //nolint:lll
	)
	if !ok {
		return 0, nil, nil
	}
	_, hasEncryptedExtensions := msgs[handshake.TypeEncryptedExtensions].(*handshake.MessageEncryptedExtensions)
	if !hasEncryptedExtensions {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, nil
	}
	if flightCtx.inboundHandshakeHandler != nil {
		if err := flightCtx.inboundHandshakeHandler(flightCtx.state.CipherSuite, items); err != nil {
			return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
		}
	}
	flightCtx.state.HandshakeRecvSequence = seq

	return Flight5, nil, nil
}

//nolint:cyclop
func flight13_1Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext13,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	state := flightCtx.state
	cfg := flightCtx.cfg

	var zeroEpoch uint16
	state.LocalEpoch.Store(zeroEpoch)
	state.RemoteEpoch.Store(zeroEpoch)
	if len(cfg.EllipticCurves) < 1 {
		return nil, nil, dtlserrors.ErrEmptyEllipticCurves
	}
	if len(cfg.LocalSignatureSchemes) < 1 {
		return nil, nil, dtlserrors.ErrNoAvailableSignatureSchemes
	}
	state.NamedCurve = cfg.EllipticCurves[0]
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
	}

	if cfg.ExtendedMasterSecret == dtlsconfig.RequestExtendedMasterSecret ||
		cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret {
		extensions = append(extensions, &extension.UseExtendedMasterSecret{
			Supported: true,
		})
	}

	extensions = append(extensions, &extension.RenegotiationInfo{
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
		extensions = append(extensions, []extension.Extension{
			&extension.SupportedEllipticCurves{
				EllipticCurves: cfg.EllipticCurves,
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}...)
	}

	if len(cfg.SupportedProtocols) > 0 {
		extensions = append(extensions, &extension.ALPN{ProtocolNameList: cfg.SupportedProtocols})
	}

	entries := make([]extension.KeyShareEntry, 0, len(cfg.EllipticCurves))
	keypairs := make(map[elliptic.Curve]*elliptic.Keypair, len(cfg.EllipticCurves))
	for _, group := range cfg.EllipticCurves {
		keypair, err := elliptic.GenerateKeypair(group)
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, extension.KeyShareEntry{
			Group: keypair.Curve, KeyExchange: keypair.PublicKey,
		})
		keypairs[keypair.Curve] = keypair
	}
	state.LocalKeyEntries = entries
	state.LocalKeypairs = keypairs
	extensions = append(extensions, &extension.KeyShare{
		ClientShares: entries,
	})

	extensions = append(extensions, &extension.SupportedVersions{
		Versions: dtlsconfig.SupportedVersionsRange(cfg.MinVersion, cfg.MaxVersion),
	})

	if len(cfg.LocalCertSignatureSchemes) > 0 {
		extensions = append(extensions, &extension.SignatureAlgorithmsCert{
			SignatureHashAlgorithms: cfg.LocalCertSignatureSchemes,
		})
	}

	if len(cfg.ServerName) > 0 {
		extensions = append(extensions, &extension.ServerName{ServerName: cfg.ServerName})
	}

	if len(cfg.LocalSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &extension.UseSRTP{
			ProtectionProfiles:  cfg.LocalSRTPProtectionProfiles,
			MasterKeyIdentifier: cfg.LocalSRTPMasterKeyIdentifier,
		})
	}

	// connection ID

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

// nolint:cyclop
func flight13_3Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext13,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	if len(flightCtx.cfg.LocalSignatureSchemes) < 1 {
		return nil, nil, dtlserrors.ErrNoAvailableSignatureSchemes
	}

	extensions := []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: flightCtx.cfg.LocalSignatureSchemes,
		},
	}

	if flightCtx.cfg.ExtendedMasterSecret == dtlsconfig.RequestExtendedMasterSecret ||
		flightCtx.cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret {
		extensions = append(extensions, &extension.UseExtendedMasterSecret{
			Supported: true,
		})
	}

	extensions = append(extensions, &extension.RenegotiationInfo{
		RenegotiatedConnection: 0,
	})

	if flightCtx.state.NamedCurve != 0 {
		extensions = append(extensions, []extension.Extension{
			&extension.SupportedEllipticCurves{
				EllipticCurves: flightCtx.cfg.EllipticCurves,
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}...)
	}

	if len(flightCtx.cfg.SupportedProtocols) > 0 {
		extensions = append(extensions, &extension.ALPN{ProtocolNameList: flightCtx.cfg.SupportedProtocols})
	}

	var localGroups []elliptic.Curve
	var newEntries []extension.KeyShareEntry
	newKeypairs := map[elliptic.Curve]*elliptic.Keypair{}
	if flightCtx.state.RemoteKeyEntries != nil {
		for _, entry := range flightCtx.state.LocalKeyEntries {
			localGroups = append(localGroups, entry.Group)
		}

		for _, entry := range *flightCtx.state.RemoteKeyEntries {
			if !slices.Contains(localGroups, entry.Group) && slices.Contains(flightCtx.cfg.EllipticCurves, entry.Group) {
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
		flightCtx.state.LocalKeyEntries = append(newEntries, flightCtx.state.LocalKeyEntries...)
		if flightCtx.state.LocalKeypairs == nil {
			flightCtx.state.LocalKeypairs = make(map[elliptic.Curve]*elliptic.Keypair, len(newKeypairs))
		}
		maps.Copy(flightCtx.state.LocalKeypairs, newKeypairs)
	}
	extensions = append(extensions, &extension.KeyShare{
		ClientShares: flightCtx.state.LocalKeyEntries,
	})

	if !slices.Contains(flightCtx.state.RemoteVersions, protocol.Version1_3) {
		return nil, nil, dtlserrors.ErrNoCommonProtocolVersion
	}
	extensions = append(extensions, &extension.SupportedVersions{
		Versions: dtlsconfig.SupportedVersionsRange(flightCtx.cfg.MinVersion, flightCtx.cfg.MaxVersion),
	})

	if len(flightCtx.cfg.LocalCertSignatureSchemes) > 0 {
		extensions = append(extensions, &extension.SignatureAlgorithmsCert{
			SignatureHashAlgorithms: flightCtx.cfg.LocalCertSignatureSchemes,
		})
	}

	if len(flightCtx.cfg.ServerName) > 0 {
		extensions = append(extensions, &extension.ServerName{ServerName: flightCtx.cfg.ServerName})
	}

	if len(flightCtx.cfg.LocalSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &extension.UseSRTP{
			ProtectionProfiles:  flightCtx.cfg.LocalSRTPProtectionProfiles,
			MasterKeyIdentifier: flightCtx.cfg.LocalSRTPMasterKeyIdentifier,
		})
	}

	if len(flightCtx.state.Cookie) > 0 {
		extensions = append(extensions, &extension.CookieExt{Cookie: flightCtx.state.Cookie})
	}

	clientHello := &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		SessionID:          flightCtx.state.SessionID,
		Cookie:             []byte{},
		Random:             flightCtx.state.LocalRandom,
		CipherSuiteIDs:     dtlsflight.CipherSuiteIDs(flightCtx.cfg.LocalCipherSuites),
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
		Extensions:         extensions,
	}

	var content handshake.Handshake

	if flightCtx.cfg.ClientHelloMessageHook != nil {
		content = handshake.Handshake{Message: flightCtx.cfg.ClientHelloMessageHook(*clientHello)}
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
