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
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// VerifyAndAppendProtectedHandshakeCacheItems verifies a DTLS 1.3 protected
// peer flight and commits it to the transcript only after Finished verifies.
func VerifyAndAppendProtectedHandshakeCacheItems(transcript *Transcript, state *dtlsstate.State13, cfg *dtlsconfig.HandshakeConfig, cipherSuite dtlsconfig.CipherSuite, items []dtlsflight.DecodedHandshakeCacheItem) error {
	if transcript == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	working, err := transcript.clone()
	if err != nil {
		return err
	}

	flight := protectedHandshakeFlight{
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
	if len(flight.peerCertificates) != 0 {
		state.PeerCertificates = flight.peerCertificates
	}

	return nil
}

type protectedHandshakeFlight struct {
	transcript  *Transcript
	state       *dtlsstate.State13
	cfg         *dtlsconfig.HandshakeConfig
	cipherSuite dtlsconfig.CipherSuite

	peerCertificates     [][]byte
	hasCertificate       bool
	hasCertificateVerify bool
	hasFinished          bool
}

func (f *protectedHandshakeFlight) process(item dtlsflight.DecodedHandshakeCacheItem) error {
	if err := item.Validate(); err != nil {
		return err
	}
	hs := item.Parsed

	switch msg := hs.Message.(type) {
	case *handshake.MessageCertificate13:
		return f.processCertificate(item.Raw, hs, msg)
	case *handshake.MessageCertificateVerify:
		return f.processCertificateVerify(item.Raw, hs, msg)
	case *handshake.MessageFinished:
		return f.processFinished(item.Raw, hs, msg)
	default:
		return f.append(item.Raw, hs)
	}
}

func (f *protectedHandshakeFlight) processCertificate(item *dtlsflight.HandshakeCacheItem, parsedHandshake *handshake.Handshake, certificate *handshake.MessageCertificate13) error {
	f.hasCertificate = true
	f.peerCertificates = rawCertificatesFromCertificate(certificate)
	if len(f.peerCertificates) == 0 {
		if item.IsClient {
			return f.append(item, parsedHandshake)
		}

		return dtlserrors.ErrInvalidCertificate
	}

	return f.append(item, parsedHandshake)
}

func (f *protectedHandshakeFlight) processCertificateVerify(item *dtlsflight.HandshakeCacheItem, parsedHandshake *handshake.Handshake, verify *handshake.MessageCertificateVerify) error {
	if !f.hasCertificate {
		return dtlserrors.ErrCertificateVerifyNoCertificate
	}
	if len(f.peerCertificates) == 0 {
		return dtlserrors.ErrCertificateVerifyNoCertificate
	}
	if err := verifyPeerCertificateVerify(
		f.transcript,
		f.cfg,
		verify,
		f.peerCertificates,
		item.IsClient,
	); err != nil {
		return err
	}
	if err := f.verifyPeerIdentity(item.IsClient); err != nil {
		return err
	}
	f.hasCertificateVerify = true

	return f.append(item, parsedHandshake)
}

func (f *protectedHandshakeFlight) processFinished(item *dtlsflight.HandshakeCacheItem, parsedHandshake *handshake.Handshake, finished *handshake.MessageFinished) error {
	if len(f.peerCertificates) != 0 && !f.hasCertificateVerify {
		return dtlserrors.ErrClientCertificateNotVerified
	}
	if item.IsClient && clientCertificateRequired(f.cfg) && len(f.peerCertificates) == 0 {
		return dtlserrors.ErrClientCertificateRequired
	}
	if err := verifyPeerFinished(
		f.transcript,
		f.state,
		f.cipherSuite,
		finished,
		item.IsClient,
	); err != nil {
		return err
	}
	if err := f.verifyConnection(); err != nil {
		return err
	}
	f.hasFinished = true

	return f.append(item, parsedHandshake)
}

func (f *protectedHandshakeFlight) append(item *dtlsflight.HandshakeCacheItem, parsedHandshake *handshake.Handshake) error {
	return appendParsedInboundHandshake(
		f.transcript,
		item.IsClient,
		f.cipherSuite,
		parsedHandshake,
		item.Data,
	)
}

func rawCertificatesFromCertificate(certificate *handshake.MessageCertificate13) [][]byte {
	out := make([][]byte, 0, len(certificate.CertificateList))
	for _, entry := range certificate.CertificateList {
		out = append(out, bytes.Clone(entry.CertificateData))
	}

	return out
}

func (f *protectedHandshakeFlight) verifyServerIdentity() error {
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

func (f *protectedHandshakeFlight) verifyPeerIdentity(isClient bool) error {
	if !isClient {
		return f.verifyServerIdentity()
	}

	var chains [][]*x509.Certificate
	var err error
	if f.cfg.ClientAuth >= dtlsconfig.VerifyClientCertIfGiven {
		certAlgs := f.cfg.LocalCertSignatureSchemes
		if len(certAlgs) == 0 {
			certAlgs = f.cfg.LocalSignatureSchemes
		}
		chains, err = dtlscrypto.VerifyClientCert(f.peerCertificates, f.cfg.ClientCAs, certAlgs)
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

func clientCertificateRequired(cfg *dtlsconfig.HandshakeConfig) bool {
	if cfg == nil {
		return false
	}

	return cfg.ClientAuth == dtlsconfig.RequireAnyClientCert ||
		cfg.ClientAuth == dtlsconfig.RequireAndVerifyClientCert
}

func (f *protectedHandshakeFlight) verifyConnection() error {
	if f.cfg.VerifyConnection != nil {
		if err := f.cfg.VerifyConnection(dtlsstate.Clone13ForVerification(f.state, f.peerCertificates)); err != nil {
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

func verifyPeerCertificateVerify(transcript *Transcript, cfg *dtlsconfig.HandshakeConfig, verify *handshake.MessageCertificateVerify, peerCertificates [][]byte, isClient bool) error {
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

	input, err := CertificateVerifyInputFromTranscript(isClient, transcript)
	if err != nil {
		return err
	}

	return dtlscrypto.VerifyCertificateVerify(input, verify.HashAlgorithm, verify.SignatureAlgorithm, verify.Signature, peerCertificates)
}

func verifyPeerFinished(transcript *Transcript, state *dtlsstate.State13, cipherSuite dtlsconfig.CipherSuite, finished *handshake.MessageFinished, isClient bool) error {
	if state == nil || cipherSuite == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}

	baseKey, err := ServerHandshakeFinishedBaseKey(state)
	if isClient {
		baseKey, err = ClientHandshakeFinishedBaseKey(state)
	}
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

func appendParsedInboundHandshake(transcript *Transcript, isClient bool, cipherSuite dtlsconfig.CipherSuite, hs *handshake.Handshake, raw []byte) error {
	canonical, err := canonicalHandshake(raw)
	if err != nil {
		return err
	}

	return appendHandshake(transcript, transcriptSenderForSide(isClient), cipherSuite, hs.Header.MessageSequence, hs.Message, canonical)
}
