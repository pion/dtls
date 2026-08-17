// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"context"
	"maps"
	"slices"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/internal/extensionnegotiation"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func flight3Parse(
	ctx context.Context,
	conn dtlsflight.Conn,
	flightCtx *handshakeContext,
) (Flight, *alert.Alert, error) {
	nextHandshakeSequence := flightCtx.state.HandshakeRecvSequence
	if flightCtx.state.RemoteEpoch() < EpochHandshake {
		pull := flight3PullServerHello(flightCtx)
		if !pull.ready {
			return 0, nil, nil
		}
		if pull.failure != nil {
			return 0, pull.failure.alert, pull.failure.err
		}

		failure := processFlight3ServerHello(flightCtx, pull.serverHello)
		if failure != nil {
			return 0, failure.alert, failure.err
		}
		failure = initializeFlight3HandshakeProtection(
			ctx,
			conn,
			flightCtx,
			pull.nextHandshakeSequence,
			pull.items,
		)
		if failure != nil {
			return abortFlight3(flightCtx, failure)
		}
		nextHandshakeSequence = pull.nextHandshakeSequence
	}

	// A DTLS flight may span multiple datagrams. Once ServerHello installs the
	// handshake read keys, resume at the first protected message instead of
	// requiring ServerHello to be pulled again. RFC 9147 Section 5.7,
	// and 5.8.1:
	// https://www.rfc-editor.org/rfc/rfc9147.html#section-5.7
	// https://www.rfc-editor.org/rfc/rfc9147.html#section-5.8.1
	protectedFlight := pullProtectedHandshakeFlight(
		flightCtx.cache,
		[]dtlsflight.HandshakeCachePullRule{
			{Typ: handshake.TypeEncryptedExtensions, Epoch: EpochHandshake, IsClient: false, Optional: false},
			{Typ: handshake.TypeCertificateRequest, Epoch: EpochHandshake, IsClient: false, Optional: true},
			{Typ: handshake.TypeCertificate, Epoch: EpochHandshake, IsClient: false, Optional: true},
			{Typ: handshake.TypeCertificateVerify, Epoch: EpochHandshake, IsClient: false, Optional: true},
			{Typ: handshake.TypeFinished, Epoch: EpochHandshake, IsClient: false, Optional: false},
		},
		nextHandshakeSequence,
	)
	if !protectedFlight.ready {
		return 0, nil, nil
	}
	if protectedFlight.failure != nil {
		return abortFlight3(flightCtx, protectedFlight.failure)
	}
	failure := handleFlight3ProtectedHandshake(flightCtx, protectedFlight.items)
	if failure != nil {
		return abortFlight3(flightCtx, failure)
	}
	flightCtx.state.HandshakeRecvSequence = protectedFlight.nextHandshakeSequence

	return Flight5, nil, nil
}

func abortFlight3(flightCtx *handshakeContext, failure *flightParseFailure) (Flight, *alert.Alert, error) {
	flightCtx.state.ResetConnectionIDs()

	return 0, failure.alert, failure.err
}

func flight3PullServerHello(
	flightCtx *handshakeContext,
) serverHelloPull {
	pull := flightCtx.cache.FullPullMapItems(
		flightCtx.state.HandshakeRecvSequence, flightCtx.state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: flightCtx.cfg.InitialEpoch, IsClient: false, Optional: false}, //nolint:lll
	)
	if pull.Err != nil {
		return serverHelloPull{
			ready:   true,
			failure: &flightParseFailure{err: pull.Err},
		}
	}
	if !pull.Ready {
		return serverHelloPull{}
	}

	serverHello, ok := pull.Messages[handshake.TypeServerHello].(*handshake.MessageServerHello)
	if !ok {
		return serverHelloPull{
			ready:   true,
			failure: newFlightParseFailure(alert.InternalError, nil),
		}
	}

	return serverHelloPull{
		nextHandshakeSequence: pull.NextSequence,
		serverHello:           serverHello,
		items:                 pull.Items,
		ready:                 true,
	}
}

func processFlight3ServerHello(
	flightCtx *handshakeContext,
	serverHello *handshake.MessageServerHello,
) *flightParseFailure {
	versions, failure := validateFlight3ServerHello(serverHello)
	if failure != nil {
		return failure
	}
	offer := flightCtx.state.LocalClientHelloSnapshots.Current()
	if err := extensionnegotiation.ValidateServerHelloResponse(offer, serverHello); err != nil {
		return newFlightParseFailure(alert.UnsupportedExtension, err)
	}
	decision := extensionnegotiation.DecideConnectionID(offer, serverHello.Extensions)
	flightCtx.state.RemoteVersions = versions
	flightCtx.state.LocalVersion = protocol.Version1_3

	selectedCipherSuite, dtlsAlert, err := selectServerHelloCipherSuite(serverHello, flightCtx.cfg)
	if err != nil {
		return newFlightParseFailure(dtlsAlert.Description, err)
	}
	flightCtx.state.CipherSuite = selectedCipherSuite
	flightCtx.state.RemoteRandom = serverHello.Random
	flightCtx.cfg.Log.Tracef("[handshake13] use cipher suite: %s", selectedCipherSuite.String())

	serverShare := serverHelloKeyShare(serverHello.Extensions)
	if serverShare == nil {
		return newFlightParseFailure(alert.IllegalParameter, dtlserrors.ErrServerKeyShareMissing)
	}

	if failure := applyFlight3ServerKeyShare(flightCtx, serverShare); failure != nil {
		return failure
	}
	flightCtx.state.CommitNegotiatedExtensions(decision)

	return nil
}

func validateFlight3ServerHello(serverHello *handshake.MessageServerHello) ([]protocol.Version, *flightParseFailure) {
	if IsHelloRetryRequest(serverHello) {
		return nil, newFlightParseFailure(
			alert.UnexpectedMessage,
			dtlserrors.ErrUnexpectedSecondHelloRetryRequest,
		)
	}

	if !serverHello.Version.Equal(protocol.Version1_2) {
		return nil, newFlightParseFailure(alert.ProtocolVersion, dtlserrors.ErrUnsupportedProtocolVersion)
	}

	versions, seenSupportedVersions, err := ServerHelloSelectedVersions(serverHello.Extensions)
	if err != nil {
		return nil, newFlightParseFailure(alert.IllegalParameter, dtlserrors.ErrInvalidServerHello)
	}
	if !seenSupportedVersions || !versions[0].Equal(protocol.Version1_3) {
		return nil, newFlightParseFailure(alert.ProtocolVersion, dtlserrors.ErrUnsupportedProtocolVersion)
	}

	return versions, nil
}

func applyFlight3ServerKeyShare(
	flightCtx *handshakeContext,
	serverShare *extension13.KeyShareEntry,
) *flightParseFailure {
	localKeypair, ok := flightCtx.state.LocalKeypairs[serverShare.Group]
	if !ok || localKeypair == nil {
		return newFlightParseFailure(alert.IllegalParameter, dtlserrors.ErrServerKeyShareUnknownGroup)
	}

	keyAgreementSecret, err := prf.PreMasterSecret(serverShare.KeyExchange, localKeypair.PrivateKey, serverShare.Group)
	if err != nil {
		return newFlightParseFailure(alert.InternalError, err)
	}
	flightCtx.state.KeyAgreementSecret = keyAgreementSecret
	flightCtx.state.SelectedGroup = serverShare.Group
	flightCtx.state.RemoteKeyEntries = cloneKeyShareEntries([]extension13.KeyShareEntry{*serverShare})
	flightCtx.state.HasRemoteKeyEntries = true

	return nil
}

func initializeFlight3HandshakeProtection(
	ctx context.Context,
	conn dtlsflight.Conn,
	flightCtx *handshakeContext,
	serverHelloSeq int,
	items []dtlsflight.DecodedHandshakeCacheItem,
) *flightParseFailure {
	if failure := flightCtx.handleInboundHandshake(items); failure != nil {
		return failure
	}
	flightCtx.state.HandshakeRecvSequence = serverHelloSeq
	if flightCtx.handshakeTrafficSecretDeriver != nil {
		if err := flightCtx.handshakeTrafficSecretDeriver(flightCtx.state); err != nil {
			return newFlightParseFailure(alert.InternalError, err)
		}
	}
	if flightCtx.handshakeRecordProtectionInitializer == nil {
		return nil
	}
	if err := flightCtx.handshakeRecordProtectionInitializer(flightCtx.state); err != nil {
		return newFlightParseFailure(alert.InternalError, err)
	}
	// During the handshake, ACK records MUST be sent with an epoch which is equal to or higher
	// than the record which is being acknowledged.
	// ....
	// if the client receives only the ServerHello and Certificate and wishes to ACK them
	// in a single record, it must do so in epoch 2, as it is required to use an epoch
	// greater than or equal to 2 and cannot yet send with any greater epoch.
	//
	// https://datatracker.ietf.org/doc/html/rfc9147#section-7
	flightCtx.state.SetLocalEpoch(EpochHandshake)
	flightCtx.state.SetRemoteEpoch(EpochHandshake)
	if conn == nil {
		return nil
	}
	if err := conn.HandleQueuedPackets(ctx); err != nil {
		return newFlightParseFailure(alert.InternalError, err)
	}

	return nil
}

func handleFlight3ProtectedHandshake(
	flightCtx *handshakeContext,
	items []dtlsflight.DecodedHandshakeCacheItem,
) *flightParseFailure {
	flightCtx.state.RemoteCertificateRequest = nil
	offer := flightCtx.state.LocalClientHelloSnapshots.Current()
	for _, item := range items {
		if item.Parsed == nil {
			continue
		}
		switch message := item.Parsed.Message.(type) {
		case *handshake.MessageEncryptedExtensions:
			if err := extensionnegotiation.ValidateResponseExtensions(offer, message.Extensions, nil); err != nil {
				return newFlightParseFailure(alert.UnsupportedExtension, err)
			}
		case *handshake.MessageCertificateRequest13:
			flightCtx.state.RemoteCertificateRequest = message
		}
	}
	if flightCtx.protectedHandshakeHandler == nil {
		return newFlightParseFailure(alert.InternalError, dtlserrors.ErrHandshakeTranscriptHashNotSelected)
	}
	if err := flightCtx.protectedHandshakeHandler(flightCtx.state.CipherSuite, items); err != nil {
		return protectedFlightParseFailure(err)
	}

	return nil
}

//nolint:cyclop,gocognit,nestif
func flight3Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	if len(flightCtx.cfg.LocalSignatureSchemes) == 0 {
		return nil, nil, dtlserrors.ErrNoAvailableSignatureSchemes
	}

	extensions := []extension.Value{
		&extension.SignatureAlgorithms{
			Schemes: dtlsflight.SignatureSchemeIDs(flightCtx.cfg.LocalSignatureSchemes),
		},
	}

	if flightCtx.cfg.ExtendedMasterSecret == dtlsconfig.RequestExtendedMasterSecret ||
		flightCtx.cfg.ExtendedMasterSecret == dtlsconfig.RequireExtendedMasterSecret {
		extensions = append(extensions, &extension12.ExtendedMasterSecret{})
	}

	extensions = append(extensions, &extension12.RenegotiationInfo{
		RenegotiatedConnection: 0,
	})

	if flightCtx.state.SelectedGroup != 0 {
		extensions = append(extensions, &extension12.SupportedPointFormats{
			PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
		})
	}

	if len(flightCtx.cfg.SupportedProtocols) > 0 {
		extensions = append(extensions, &extension.ALPNOffer{Protocols: flightCtx.cfg.SupportedProtocols})
	}

	var localGroups []elliptic.Curve
	var newEntries []extension13.KeyShareEntry
	newKeypairs := map[elliptic.Curve]*elliptic.Keypair{}
	if flightCtx.state.HasRemoteKeyEntries {
		for _, entry := range flightCtx.state.LocalKeyEntries {
			localGroups = append(localGroups, entry.Group)
		}

		for _, entry := range flightCtx.state.RemoteKeyEntries {
			if !slices.Contains(localGroups, entry.Group) && slices.Contains(flightCtx.cfg.EllipticCurves, entry.Group) {
				keypair, err := elliptic.GenerateKeypair(entry.Group)
				if err != nil {
					return nil, nil, err
				}
				newEntries = append(newEntries, extension13.KeyShareEntry{
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
	extensions = append(extensions, &extension.SupportedGroups{
		Groups: supportedGroupsForKeyShares(flightCtx.state.LocalKeyEntries, flightCtx.cfg.EllipticCurves),
	})
	extensions = append(extensions, &extension13.ClientKeyShare{
		Shares: flightCtx.state.LocalKeyEntries,
	})

	if !slices.Contains(flightCtx.state.RemoteVersions, protocol.Version1_3) {
		return nil, nil, dtlserrors.ErrNoCommonProtocolVersion
	}
	extensions = append(extensions, &extension13.OfferedVersions{
		Versions: dtlsconfig.SupportedVersionsRange(flightCtx.cfg.MinVersion, flightCtx.cfg.MaxVersion),
	})

	if len(flightCtx.cfg.LocalCertSignatureSchemes) > 0 {
		extensions = append(extensions, &extension.CertificateSignatureAlgorithms{
			Schemes: dtlsflight.SignatureSchemeIDs(flightCtx.cfg.LocalCertSignatureSchemes),
		})
	}

	if len(flightCtx.cfg.ServerName) > 0 {
		extensions = append(extensions, &extension.ServerNameOffer{ServerName: flightCtx.cfg.ServerName})
	}

	if len(flightCtx.cfg.LocalSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &extension.SRTPOffer{
			ProtectionProfiles:  flightCtx.cfg.LocalSRTPProtectionProfiles,
			MasterKeyIdentifier: flightCtx.cfg.LocalSRTPMasterKeyIdentifier,
		})
	}

	localCID, localCIDOffered := extensionnegotiation.ConnectionIDOffer(flightCtx.state.LocalClientHelloSnapshots.Current()) //nolint:lll
	if flightCtx.cfg.ConnectionIDGenerator != nil && localCIDOffered {
		extensions = append(extensions, &extension.ConnectionID{CID: bytes.Clone(localCID)})
	}

	if len(flightCtx.state.Cookie) > 0 {
		extensions = append(extensions, &extension13.Cookie{Cookie: flightCtx.state.Cookie})
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

	clientHello, snapshot, err := extensionnegotiation.FinalizeClientHello(clientHello, flightCtx.cfg.ClientHelloMessageHook) //nolint:lll
	if err != nil {
		return nil, nil, err
	}
	if err := flightCtx.state.RecordLocalClientHello(snapshot); err != nil {
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

func supportedGroupsForKeyShares(
	shares []extension13.KeyShareEntry,
	configured []elliptic.Curve,
) []elliptic.Curve {
	groups := make([]elliptic.Curve, 0, len(configured))
	for _, share := range shares {
		if !slices.Contains(groups, share.Group) {
			groups = append(groups, share.Group)
		}
	}
	for _, group := range configured {
		if !slices.Contains(groups, group) {
			groups = append(groups, group)
		}
	}

	return groups
}
