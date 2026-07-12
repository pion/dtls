// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"bytes"
	"crypto/x509"
	"fmt"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlscrypto "github.com/pion/dtls/v3/internal/handshakecrypto"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// VerifyAndAppendProtectedHandshakeCacheItems13 verifies a DTLS 1.3 protected
// server flight and commits it to the transcript only after Finished verifies.
func VerifyAndAppendProtectedHandshakeCacheItems13(
	transcript *Transcript,
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
	cipherSuite dtlsconfig.CipherSuite,
	items []*dtlsflight.HandshakeCacheItem,
) error {
	if transcript == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	working, err := transcript.clone()
	if err != nil {
		return err
	}

	flight := protectedHandshakeFlight13{
		transcript:  working,
		state:       state,
		cfg:         cfg,
		cipherSuite: cipherSuite,
	}
	for _, item := range items {
		if err := flight.process(item); err != nil {
			return err
		}
	}
	if !flight.hasFinished {
		return dtlserrors.ErrVerifyDataMismatch
	}

	if err := transcript.replaceWith(working); err != nil {
		return err
	}
	if flight.hasCertificate {
		state.PeerCertificates = flight.peerCertificates
	}

	return nil
}

type protectedHandshakeFlight13 struct {
	transcript  *Transcript
	state       *dtlsstate.State13
	cfg         *dtlsconfig.HandshakeConfig
	cipherSuite dtlsconfig.CipherSuite

	peerCertificates     [][]byte
	hasCertificate       bool
	hasCertificateVerify bool
	hasFinished          bool
}

func (f *protectedHandshakeFlight13) process(item *dtlsflight.HandshakeCacheItem) error {
	hs, err := parseProtectedHandshakeCacheItem13(item)
	if err != nil {
		return err
	}

	switch msg := hs.Message.(type) {
	case *handshake.MessageCertificate13:
		return f.processCertificate(item, hs, msg)
	case *handshake.MessageCertificateVerify:
		return f.processCertificateVerify(item, hs, msg)
	case *handshake.MessageFinished:
		return f.processFinished(item, hs, msg)
	default:
		return f.append(item, hs)
	}
}

func (f *protectedHandshakeFlight13) processCertificate(
	item *dtlsflight.HandshakeCacheItem,
	parsedHandshake *handshake.Handshake,
	certificate *handshake.MessageCertificate13,
) error {
	f.hasCertificate = true
	f.peerCertificates = rawCertificatesFromCertificate13(certificate)
	if len(f.peerCertificates) == 0 {
		return dtlserrors.ErrInvalidCertificate
	}

	return f.append(item, parsedHandshake)
}

func (f *protectedHandshakeFlight13) processCertificateVerify(
	item *dtlsflight.HandshakeCacheItem,
	parsedHandshake *handshake.Handshake,
	verify *handshake.MessageCertificateVerify,
) error {
	if !f.hasCertificate {
		return dtlserrors.ErrCertificateVerifyNoCertificate
	}
	if err := verifyServerCertificateVerify13(f.transcript, f.cfg, verify, f.peerCertificates); err != nil {
		return err
	}
	if err := f.verifyServerIdentity(); err != nil {
		return err
	}
	f.hasCertificateVerify = true

	return f.append(item, parsedHandshake)
}

func (f *protectedHandshakeFlight13) processFinished(
	item *dtlsflight.HandshakeCacheItem,
	parsedHandshake *handshake.Handshake,
	finished *handshake.MessageFinished,
) error {
	if f.hasCertificate && !f.hasCertificateVerify {
		return dtlserrors.ErrClientCertificateNotVerified
	}
	if err := verifyServerFinished13(f.transcript, f.state, f.cipherSuite, finished); err != nil {
		return err
	}
	if err := f.verifyConnection(); err != nil {
		return err
	}
	f.hasFinished = true

	return f.append(item, parsedHandshake)
}

func (f *protectedHandshakeFlight13) append(
	item *dtlsflight.HandshakeCacheItem,
	parsedHandshake *handshake.Handshake,
) error {
	return appendParsedInboundHandshake13(
		f.transcript,
		item.IsClient,
		f.cipherSuite,
		parsedHandshake,
		item.Data,
	)
}

func parseProtectedHandshakeCacheItem13(item *dtlsflight.HandshakeCacheItem) (*handshake.Handshake, error) {
	if item == nil {
		return nil, dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	header := &handshake.Header{}
	if err := header.Unmarshal(item.Data); err != nil {
		return nil, err
	}
	if header.Type != item.Typ ||
		header.MessageSequence != item.MessageSequence ||
		header.FragmentOffset != 0 ||
		header.FragmentLength != header.Length ||
		len(item.Data) != handshake.HeaderLength+int(header.Length) {
		return nil, dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	msg, err := protectedHandshakeMessage13(header.Type, item.Data[handshake.HeaderLength:])
	if err != nil {
		return nil, err
	}

	return &handshake.Handshake{
		Header:  *header,
		Message: msg,
	}, nil
}

func protectedHandshakeMessage13(typ handshake.Type, body []byte) (handshake.Message, error) {
	var msg handshake.Message
	switch typ {
	case handshake.TypeEncryptedExtensions:
		msg = &handshake.MessageEncryptedExtensions{}
	case handshake.TypeCertificateRequest:
		msg = &handshake.MessageCertificateRequest13{}
	case handshake.TypeCertificate:
		msg = &handshake.MessageCertificate13{}
	case handshake.TypeCertificateVerify:
		msg = &handshake.MessageCertificateVerify{}
	case handshake.TypeFinished:
		msg = &handshake.MessageFinished{}
	default:
		return nil, dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}
	if err := msg.Unmarshal(body); err != nil {
		return nil, err
	}

	return msg, nil
}

func rawCertificatesFromCertificate13(certificate *handshake.MessageCertificate13) [][]byte {
	out := make([][]byte, 0, len(certificate.CertificateList))
	for _, entry := range certificate.CertificateList {
		out = append(out, append([]byte(nil), entry.CertificateData...))
	}

	return out
}

func (f *protectedHandshakeFlight13) verifyServerIdentity() error {
	var chains [][]*x509.Certificate
	var err error
	if !f.cfg.InsecureSkipVerify {
		certAlgs := f.cfg.LocalCertSignatureSchemes
		if len(certAlgs) == 0 {
			certAlgs = f.cfg.LocalSignatureSchemes
		}
		chains, err = dtlscrypto.VerifyServerCert(
			f.peerCertificates, f.cfg.RootCAs, f.cfg.ServerName, certAlgs,
		)
		if err != nil {
			return certificateVerificationError(err)
		}
	}
	if f.cfg.VerifyPeerCertificate != nil {
		if err = f.cfg.VerifyPeerCertificate(f.peerCertificates, chains); err != nil {
			return certificateVerificationError(err)
		}
	}

	return nil
}

func (f *protectedHandshakeFlight13) verifyConnection() error {
	if f.cfg.VerifyConnection != nil {
		if err := f.cfg.VerifyConnection(cloneState13ForVerifyConnection(f.state, f.peerCertificates)); err != nil {
			return certificateVerificationError(err)
		}
	}

	return nil
}

func certificateVerificationError(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%w: %w", dtlserrors.ErrCertificateVerificationFailed, err)
}

func cloneState13ForVerifyConnection(state *dtlsstate.State13, peerCertificates [][]byte) *dtlsstate.State13 {
	common := &dtlsstate.Common{
		PeerCertificates: util.CloneByteSlices(peerCertificates),
		LocalVersion:     protocol.Version1_3,
	}
	if state == nil || state.Common == nil {
		return &dtlsstate.State13{Common: common}
	}

	common.LocalSequenceNumber = append([]uint64(nil), state.LocalSequenceNumber...)
	common.RemoteSequenceNumber = append([]uint64(nil), state.RemoteSequenceNumber...)
	common.LocalRandom = state.LocalRandom
	common.RemoteRandom = state.RemoteRandom
	common.CipherSuite = state.CipherSuite
	common.IdentityHint = bytes.Clone(state.IdentityHint)
	common.SessionID = bytes.Clone(state.SessionID)
	common.NegotiatedProtocol = state.NegotiatedProtocol
	common.RemoteSRTPMasterKeyIdentifier = bytes.Clone(state.RemoteSRTPMasterKeyIdentifier)
	common.RemoteConnectionID = bytes.Clone(state.RemoteConnectionID)
	common.IsClient = state.IsClient
	common.ServerName = state.ServerName
	common.PeerSupportedProtocols = append([]string(nil), state.PeerSupportedProtocols...)
	common.RemoteVersions = append([]protocol.Version(nil), state.RemoteVersions...)
	if !state.LocalVersion.Equal(protocol.Version{}) {
		common.LocalVersion = state.LocalVersion
	}
	if localEpoch, ok := state.LocalEpoch.Load().(uint16); ok {
		common.LocalEpoch.Store(localEpoch)
	}
	if remoteEpoch, ok := state.RemoteEpoch.Load().(uint16); ok {
		common.RemoteEpoch.Store(remoteEpoch)
	}
	if profile, ok := state.SRTPProtectionProfile.Load().(extension.SRTPProtectionProfile); ok {
		common.SRTPProtectionProfile.Store(profile)
	}
	if localCID := state.GetLocalConnectionID(); localCID != nil {
		common.SetLocalConnectionID(bytes.Clone(localCID))
	}
	var remoteKeyEntries *[]extension.KeyShareEntry
	if state.RemoteKeyEntries != nil {
		entries := append([]extension.KeyShareEntry(nil), (*state.RemoteKeyEntries)...)
		remoteKeyEntries = &entries
	}

	return &dtlsstate.State13{
		Common:                common,
		KeySchedule:           cloneKeySchedule13(state.KeySchedule),
		KeyAgreementSecret:    bytes.Clone(state.KeyAgreementSecret),
		SelectedGroup:         state.SelectedGroup,
		LocalKeyEntries:       append([]extension.KeyShareEntry(nil), state.LocalKeyEntries...),
		RemoteKeyEntries:      remoteKeyEntries,
		RemoteGroups:          append([]elliptic.Curve(nil), state.RemoteGroups...),
		Cookie:                bytes.Clone(state.Cookie),
		HandshakeSendSequence: state.HandshakeSendSequence,
		HandshakeRecvSequence: state.HandshakeRecvSequence,
		RemoteSignatureSchemes: append(
			[]signaturehash.Algorithm(nil), state.RemoteSignatureSchemes...,
		),
		RemoteCertSignatureSchemes: append(
			[]signaturehash.Algorithm(nil), state.RemoteCertSignatureSchemes...,
		),
	}
}

func cloneKeySchedule13(in dtlsstate.KeySchedule) dtlsstate.KeySchedule {
	return dtlsstate.KeySchedule{
		EarlySecret:                     bytes.Clone(in.EarlySecret),
		HandshakeSecret:                 bytes.Clone(in.HandshakeSecret),
		MasterSecret:                    bytes.Clone(in.MasterSecret),
		HandshakeTraffic:                cloneTrafficSecrets13(in.HandshakeTraffic),
		ClientApplicationTrafficSecret0: bytes.Clone(in.ClientApplicationTrafficSecret0),
		ServerApplicationTrafficSecret0: bytes.Clone(in.ServerApplicationTrafficSecret0),
		ExporterMasterSecret:            bytes.Clone(in.ExporterMasterSecret),
		ResumptionMasterSecret:          bytes.Clone(in.ResumptionMasterSecret),
	}
}

func cloneTrafficSecrets13(in dtlsstate.TrafficSecrets) dtlsstate.TrafficSecrets {
	return dtlsstate.TrafficSecrets{
		Client: bytes.Clone(in.Client),
		Server: bytes.Clone(in.Server),
	}
}

func verifyServerCertificateVerify13(
	transcript *Transcript,
	cfg *dtlsconfig.HandshakeConfig,
	verify *handshake.MessageCertificateVerify,
	peerCertificates [][]byte,
) error {
	if cfg == nil {
		return dtlserrors.ErrNoAvailableSignatureSchemes
	}
	var validSignatureScheme bool
	for _, alg := range cfg.LocalSignatureSchemes {
		if alg.Hash == verify.HashAlgorithm && alg.Signature == verify.SignatureAlgorithm {
			validSignatureScheme = true

			break
		}
	}
	if !validSignatureScheme {
		return dtlserrors.ErrNoAvailableSignatureSchemes
	}

	input, err := CertificateVerifyInputFromTranscript(false, transcript)
	if err != nil {
		return err
	}

	return dtlscrypto.VerifyCertificateVerify(
		input,
		verify.HashAlgorithm,
		verify.SignatureAlgorithm,
		verify.Signature,
		peerCertificates,
	)
}

func verifyServerFinished13(
	transcript *Transcript,
	state *dtlsstate.State13,
	cipherSuite dtlsconfig.CipherSuite,
	finished *handshake.MessageFinished,
) error {
	if state == nil || cipherSuite == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}

	baseKey, err := ServerHandshakeFinishedBaseKey(state)
	if err != nil {
		return err
	}

	return VerifyFinishedDataFromTranscript(
		cipherSuite.HashFunc(),
		baseKey,
		transcript,
		finished.VerifyData,
	)
}

func appendParsedInboundHandshake13(
	transcript *Transcript,
	isClient bool,
	cipherSuite dtlsconfig.CipherSuite,
	hs *handshake.Handshake,
	raw []byte,
) error {
	canonical, err := canonicalHandshake(raw)
	if err != nil {
		return err
	}

	return appendHandshake13(
		transcript,
		transcriptSenderForSide13(isClient),
		cipherSuite,
		hs.Header.MessageSequence,
		hs.Message,
		canonical,
	)
}
