// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"context"
	"crypto"
	"slices"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// flight4Parse processes the client's protected final flight. The parser is
// keyed by the server's current flight (Flight 4), even tho the messages on
// the wire are the client's Flight 5.
func flight4Parse(
	_ context.Context,
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) (Flight, *alert.Alert, error) {
	protectedFlight := pullProtectedHandshakeFlight(
		flightCtx.cache,
		[]dtlsflight.HandshakeCachePullRule{
			{Typ: handshake.TypeCertificate, Epoch: EpochHandshake, IsClient: true, Optional: true},
			{Typ: handshake.TypeCertificateVerify, Epoch: EpochHandshake, IsClient: true, Optional: true},
			{Typ: handshake.TypeFinished, Epoch: EpochHandshake, IsClient: true, Optional: false},
		},
		flightCtx.state.HandshakeRecvSequence,
	)
	if !protectedFlight.ready {
		return 0, nil, nil
	}
	if protectedFlight.failure != nil {
		return 0, protectedFlight.failure.alert, protectedFlight.failure.err
	}

	if flightCtx.protectedHandshakeHandler == nil {
		return 0, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError},
			dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if err := flightCtx.protectedHandshakeHandler(flightCtx.state.CipherSuite, protectedFlight.items); err != nil {
		failure := protectedFlightParseFailure(err)

		return 0, failure.alert, failure.err
	}
	flightCtx.state.HandshakeRecvSequence = protectedFlight.nextHandshakeSequence

	// Returning the current flight marks the server's last receive flight.
	return Flight4, nil, nil
}

func selectClientKeyShare(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
) bool {
	selectedGroup, ok := preferredClientGroup(state, cfg)
	if !ok {
		return false
	}
	state.SelectedGroup = selectedGroup

	return true
}

func generateClientKeyShareSecret(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
) *clientHelloExtensionFailure {
	selectedGroup, ok := preferredClientGroup(state, cfg)
	if !ok {
		if state.RemoteGroups != nil {
			return newClientHelloExtensionFailure(alert.InsufficientSecurity, dtlserrors.ErrNoSupportedEllipticCurves)
		}

		return nil
	}
	state.SelectedGroup = selectedGroup

	selectedEntry, ok := clientKeyShareForGroup(state, selectedGroup)
	if !ok {
		return newClientHelloExtensionFailure(alert.IllegalParameter, dtlserrors.ErrInvalidClientHello)
	}

	if needsClientKeypair(state) {
		keypair, err := elliptic.GenerateKeypairForPeer(state.SelectedGroup, selectedEntry.KeyExchange)
		if err != nil {
			return newClientHelloExtensionFailure(alert.IllegalParameter, err)
		}
		state.LocalKeypair = keypair
	}

	keyAgreementSecret, err := prf.PreMasterSecret(
		selectedEntry.KeyExchange,
		state.LocalKeypair.PrivateKey,
		state.SelectedGroup,
	)
	if err != nil {
		return newClientHelloExtensionFailure(alert.IllegalParameter, err)
	}
	state.KeyAgreementSecret = keyAgreementSecret

	return nil
}

func matchingClientKeyShare(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
) (extension13.KeyShareEntry, bool) {
	selectedGroup, ok := preferredClientGroup(state, cfg)
	if !ok {
		return extension13.KeyShareEntry{}, false
	}

	return clientKeyShareForGroup(state, selectedGroup)
}

func preferredClientGroup(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
) (elliptic.Curve, bool) {
	if state.RemoteGroups == nil {
		return 0, false
	}

	for _, group := range cfg.EllipticCurves {
		if slices.Contains(state.RemoteGroups, group) {
			return group, true
		}
	}

	return 0, false
}

func clientKeyShareForGroup(
	state *dtlsstate.State13,
	group elliptic.Curve,
) (extension13.KeyShareEntry, bool) {
	if !state.HasRemoteKeyEntries {
		return extension13.KeyShareEntry{}, false
	}
	for _, entry := range state.RemoteKeyEntries {
		if entry.Group == group {
			return entry, true
		}
	}

	return extension13.KeyShareEntry{}, false
}

func needsClientKeypair(state *dtlsstate.State13) bool {
	return state.LocalKeypair == nil ||
		state.LocalKeypair.Curve != state.SelectedGroup ||
		state.SelectedGroup == elliptic.X25519MLKEM768
}

func flight4Generate( //nolint:cyclop
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	state := flightCtx.state
	cfg := flightCtx.cfg

	if state.CipherSuite == nil {
		return nil, nil, dtlserrors.ErrCipherSuiteUnset
	}
	if state.LocalKeypair == nil {
		return nil, nil, dtlserrors.ErrServerKeyShareMissing
	}

	certificate, err := cfg.GetCertificate(&dtlsconfig.ClientHelloInfo{
		ServerName:   state.ServerName,
		CipherSuites: []ciphersuite.ID{state.CipherSuite.ID()},
		RandomBytes:  state.RemoteRandom.RandomBytes,
	})
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
	}
	if certificate == nil || len(certificate.Certificate) == 0 {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure},
			dtlserrors.ErrNoCertificates
	}

	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure},
			dtlserrors.ErrInvalidPrivateKey
	}

	commonSignatureSchemes := make([]signaturehash.Algorithm, 0, len(state.RemoteSignatureSchemes))
	for _, remote := range state.RemoteSignatureSchemes {
		if slices.Contains(cfg.LocalSignatureSchemes, remote) {
			commonSignatureSchemes = append(commonSignatureSchemes, remote)
		}
	}

	signatureScheme, err := signaturehash.SelectSignatureScheme13(commonSignatureSchemes, signer)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, err
	}

	cipherSuiteID := uint16(state.CipherSuite.ID())
	serverHelloExtensions := []extension.Value{
		&extension13.SelectedVersion{
			Version: protocol.Version1_3,
		},
	}
	serverHelloExtensions = append(serverHelloExtensions, &extension13.ServerKeyShare{
		Share: extension13.KeyShareEntry{
			Group:       state.LocalKeypair.Curve,
			KeyExchange: state.LocalKeypair.PublicKey,
		},
	})
	offer := state.RemoteClientHelloSnapshots.Current()
	srtpDecision, err := negotiation.NegotiateSRTP(
		offer, cfg.LocalSRTPProtectionProfiles, cfg.LocalSRTPMasterKeyIdentifier,
	)
	if err != nil {
		return nil, nil, err
	}
	if cfg.ConnectionIDGenerator != nil && offer.Offered(extension.TypeConnectionID) {
		localCID := state.LocalConnectionID()
		if !state.CID.Negotiated {
			localCID = bytes.Clone(cfg.ConnectionIDGenerator())
		}
		serverHelloExtensions = append(serverHelloExtensions, &extension.ConnectionID{CID: bytes.Clone(localCID)})
		if offer.Offered(extension.TypeReturnRoutabilityCheck) {
			serverHelloExtensions = append(serverHelloExtensions, &extension.ReturnRoutabilityCheck{})
		}
	}
	serverHelloMessage := &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		Random:            state.LocalRandom,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
		Extensions:        serverHelloExtensions,
	}
	if _, err = serverHelloMessage.Marshal(); err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	decision := negotiation.DecideConnectionID(offer, serverHelloExtensions)

	serverHello := &dtlsflight.Packet{
		Record: &recordlayer.RecordLayer{
			Header:  recordlayer.Header{Version: protocol.Version1_2},
			Content: &handshake.Handshake{Message: serverHelloMessage},
		},
	}

	encryptedExtensionsList := []extension.Value{}
	if srtpDecision.ProtectionProfile != 0 {
		encryptedExtensionsList = append(encryptedExtensionsList, &extension.SRTPSelection{
			ProtectionProfile:   srtpDecision.ProtectionProfile,
			MasterKeyIdentifier: bytes.Clone(srtpDecision.MasterKeyIdentifier),
		})
	}
	encryptedExtensions := HandshakePacket(&handshake.MessageEncryptedExtensions{
		Extensions: encryptedExtensionsList,
	})
	encryptedExtensions.ResetLocalSequenceNumber = true

	pkts := []*dtlsflight.Packet{
		serverHello,
		encryptedExtensions,
	}
	if cfg.ClientAuth > dtlsconfig.NoClientCert {
		// RFC 8446 Section 4.3.2 requires signature_algorithms in the request.
		// https://www.rfc-editor.org/rfc/rfc9147.html#section-5.1
		// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.3.2
		certificateRequestExtensions := []extension.Value{
			&extension.SignatureAlgorithms{
				Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes),
			},
		}
		if cfg.ClientCAs != nil {
			certificateRequestExtensions = append(certificateRequestExtensions, &extension13.CertificateAuthorities{
				// nolint:staticcheck // ignoring tlsCert.RootCAs.Subjects is deprecated ERR
				// because cert does not come from SystemCertPool and it's ok if certificate
				// authorities is empty.
				Authorities: cfg.ClientCAs.Subjects(),
			})
		}
		pkts = append(pkts, HandshakePacket(&handshake.MessageCertificateRequest13{
			Extensions: certificateRequestExtensions,
		}))
	}
	pkts = append(pkts,
		HandshakePacket(&handshake.MessageCertificate13{
			CertificateList: certificateEntries(certificate.Certificate),
		}),
		CertificateVerifyPacket(
			&handshake.MessageCertificateVerify{
				HashAlgorithm:      signatureScheme.Hash,
				SignatureAlgorithm: signatureScheme.Signature,
			},
			signer,
		),
		HandshakePacket(&handshake.MessageFinished{}),
	)
	state.CommitNegotiatedExtensions(decision)
	dtlsflight.CommitSRTP(state.Common, srtpDecision)

	return pkts, nil, nil
}
