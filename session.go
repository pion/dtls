// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
)

// Session store data needed in resumption.
// Entries without authentication metadata are ignored. Sessions are rechecked
// against the current authentication policy.
type Session struct {
	// ID store session id
	ID []byte
	// Secret store session master secret
	Secret []byte //nolint:gosec // no real risk of exporting the secret.
	// Version identifies sessions carrying authentication and negotiation metadata.
	Version              uint8
	IsClient             bool
	CipherSuiteID        CipherSuiteID
	ExtendedMasterSecret bool
	PeerCertificates     [][]byte
	IdentityHint         []byte
	PSKHash              [sha256.Size]byte
}

func (s *State) session() Session {
	return Session{
		ID: bytes.Clone(s.SessionID), Secret: bytes.Clone(s.masterSecret),
		Version: 1, IsClient: s.isClient, CipherSuiteID: s.cipherSuite.ID(),
		ExtendedMasterSecret: s.extendedMasterSecret, PeerCertificates: s.PeerCertificates,
		IdentityHint: bytes.Clone(s.IdentityHint), PSKHash: s.pskHash,
	}
}

// Legacy entries lack the metadata needed to authenticate a resumed session.
func (s Session) usable(cfg *handshakeConfig, isClient bool) bool { //nolint:cyclop
	if s.Version != 1 || s.IsClient != isClient || len(s.ID) == 0 || len(s.Secret) != 48 {
		return false
	}
	if cfg.extendedMasterSecret == RequireExtendedMasterSecret && !s.ExtendedMasterSecret {
		return false
	}
	if cfg.extendedMasterSecret == DisableExtendedMasterSecret && s.ExtendedMasterSecret {
		return false
	}
	var suite CipherSuite
	for _, candidate := range cfg.localCipherSuites {
		if candidate.ID() == s.CipherSuiteID {
			suite = candidate

			break
		}
	}
	if suite == nil {
		return false
	}
	if suite.AuthenticationType() == CipherSuiteAuthenticationTypePreSharedKey {
		if cfg.localPSKCallback == nil {
			return false
		}
		key, err := cfg.localPSKCallback(s.IdentityHint)

		return err == nil && sha256.Sum256(key) == s.PSKHash
	}
	if isClient {
		if len(s.PeerCertificates) == 0 {
			return false
		}
		// Check the cached chain and custom policy before offering resumption
		// so that changes can fall back to the server's current certificate.
		chains, err := verifySessionCertificate(s.PeerCertificates, cfg)
		if err != nil {
			return false
		}

		return cfg.verifyPeerCertificate == nil || cfg.verifyPeerCertificate(s.PeerCertificates, chains) == nil
	}

	// Client-authenticated sessions are not stored by this implementation.
	return cfg.clientAuth == NoClientCert || cfg.clientAuth == RequestClientCert
}

func verifyResumedConnection(state *State, cfg *handshakeConfig) error {
	if state.isClient && state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate {
		// The peer callback already accepted the cached certificate before we
		// offered resumption. Recheck expiry without calling the callback twice.
		_, err := verifySessionCertificate(state.PeerCertificates, cfg)
		if err != nil {
			return err
		}
	}
	if cfg.verifyConnection != nil {
		clone, err := state.clone()
		if err != nil {
			return err
		}

		return cfg.verifyConnection(clone)
	}

	return nil
}

func verifySessionCertificate(rawCertificates [][]byte, cfg *handshakeConfig) ([][]*x509.Certificate, error) {
	if cfg.insecureSkipVerify {
		return nil, nil //nolint:nilnil // Normal certificate verification is explicitly disabled.
	}
	algs := cfg.localCertSignatureSchemes
	if len(algs) == 0 {
		algs = cfg.localSignatureSchemes
	}

	return verifyServerCert(rawCertificates, cfg.rootCAs, cfg.serverName, algs)
}

// SessionStore defines methods needed for session resumption.
// Stores must preserve every Session field, including authentication metadata.
// Entries containing only an ID and Secret are ignored and require a full handshake.
type SessionStore interface {
	// Set save a session.
	// For client, use server name as key.
	// For server, use session id.
	Set(key []byte, s Session) error
	// Get fetch a session.
	Get(key []byte) (Session, error)
	// Del clean saved session.
	Del(key []byte) error
}
