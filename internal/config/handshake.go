// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package config contains internal handshake configuration.
package config

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v4/internal/ech"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlscrypto "github.com/pion/dtls/v4/internal/handshakecrypto"
	internalstate "github.com/pion/dtls/v4/internal/state"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/logging"
)

type ClientAuthType int

const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

type ExtendedMasterSecretType int

const (
	RequestExtendedMasterSecret ExtendedMasterSecretType = iota
	RequireExtendedMasterSecret
	DisableExtendedMasterSecret
)

type (
	CipherSuite           = cryptosuite.Suite
	SRTPProtectionProfile = extension.SRTPProtectionProfile
)

type ClientHelloInfo struct {
	ServerName        string
	CipherSuites      []cryptosuite.ID
	RandomBytes       [handshake.RandomBytesLength]byte
	Hello             *handshake.MessageClientHello
	HelloRetryRequest bool
	Context           func() context.Context
	Conn              net.Conn
}

type CertificateRequestInfo struct {
	CertificateTypes []clientcertificate.Type
	AcceptableCAs    [][]byte
	SignatureSchemes []signaturehash.Algorithm
	Version          protocol.Version
}

func (cri *CertificateRequestInfo) SupportsCertificate(certificate *tls.Certificate) error {
	if cri.CertificateTypes != nil {
		signer, ok := certificate.PrivateKey.(crypto.Signer)
		if !ok {
			return dtlserrors.ErrInvalidPrivateKey
		}
		var certificateType clientcertificate.Type
		switch signer.Public().(type) {
		case *rsa.PublicKey:
			certificateType = clientcertificate.RSASign
		case *ecdsa.PublicKey, ed25519.PublicKey:
			certificateType = clientcertificate.ECDSASign
		default:
			return dtlserrors.ErrInvalidPrivateKey
		}
		if !slices.Contains(cri.CertificateTypes, certificateType) {
			return dtlserrors.ErrNotAcceptableCertificateChain
		}
	}
	if len(cri.SignatureSchemes) > 0 {
		if _, err := signaturehash.SelectSignatureScheme(cri.SignatureSchemes, certificate.PrivateKey, cri.Version); err != nil {
			return err
		}
	}

	return SupportsCertificate(cri.AcceptableCAs, certificate)
}

func SupportsCertificate(acceptableCAs [][]byte, c *tls.Certificate) error {
	if len(acceptableCAs) == 0 {
		return nil
	}

	for j, cert := range c.Certificate {
		x509Cert := c.Leaf
		if j != 0 || x509Cert == nil {
			var err error
			if x509Cert, err = x509.ParseCertificate(cert); err != nil {
				return fmt.Errorf("failed to parse certificate #%d in the chain: %w", j, err)
			}
		}

		for _, ca := range acceptableCAs {
			if bytes.Equal(x509Cert.RawIssuer, ca) {
				return nil
			}
		}
	}

	return dtlserrors.ErrNotAcceptableCertificateChain
}

type HandshakeConfig struct {
	// ECHConfigList enables initial-offer construction internally.
	ECHConfigList      []byte
	ECHKeys            []ech.Key
	GetECHKeys         func(*ClientHelloInfo) ([]ech.Key, error)
	ECHRejectionVerify func(internalstate.Active) error
	PSKIdentityLimit   int
	// SelectPSK returns the selected offer index, key, and hash, or a nil key if none match.
	SelectPSK                     func(identities [][]byte) (index int, key []byte, hash crypto.Hash, err error)
	GetPSKs                       func() ([]internalstate.PSK, error)
	LocalPSKCallback              func([]byte) ([]byte, error)
	LocalPSKIdentityHint          []byte
	LocalCipherSuites             []CipherSuite
	LocalSignatureSchemes         []signaturehash.Algorithm
	LocalCertSignatureSchemes     []signaturehash.Algorithm
	ExtendedMasterSecret          ExtendedMasterSecretType
	LocalSRTPProtectionProfiles   []SRTPProtectionProfile
	LocalSRTPMasterKeyIdentifier  []byte
	ServerName                    string
	SupportedProtocols            []string
	ClientAuth                    ClientAuthType
	LocalCertificates             []tls.Certificate
	InsecureSkipVerify            bool
	VerifyPeerCertificate         func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	VerifyConnection              func(internalstate.Active) error
	HasSessionStore               bool
	MaxEarlyDataSize              uint32
	EnableEarlyData               bool
	ClaimEarlyData                func(ticket []byte, expiresAt time.Time) (bool, error)
	GetSession                    func(key []byte) (internalstate.Session, error)
	SetSession                    func(key []byte, session internalstate.Session) error
	SetSessionTicket              func(key, id, secret []byte, ticket internalstate.SessionTicket) error
	GetSessionTicket              func(key []byte, serverName string) (*internalstate.PSK, error)
	DelSession                    func(key []byte) error
	RootCAs                       *x509.CertPool
	ClientCAs                     *x509.CertPool
	InitialRetransmitInterval     time.Duration
	DisableRetransmitBackoff      bool
	EllipticCurves                []elliptic.Curve
	InsecureSkipHelloVerify       bool
	ReceiveCIDLength              int
	ConnectionIDGenerator         func() []byte
	EnableRRC                     bool
	HelloRandomBytesGenerator     func() [handshake.RandomBytesLength]byte
	Log                           logging.LeveledLogger
	KeyLogWriter                  io.Writer
	LocalGetCertificate           func(*ClientHelloInfo) (*tls.Certificate, error)
	LocalGetClientCertificate     func(*CertificateRequestInfo) (*tls.Certificate, error)
	InitialEpoch                  uint64
	ClientHelloMessageHook        func(handshake.MessageClientHello) handshake.Message
	ServerHelloMessageHook        func(handshake.MessageServerHello) handshake.Message
	CertificateRequestMessageHook func(handshake.MessageCertificateRequest) handshake.Message
	ResumeState                   internalstate.Active
	MinVersion                    protocol.Version
	MaxVersion                    protocol.Version
	TimerFactory                  func(time.Duration) Timer

	nameToCertificate map[string]*tls.Certificate
	mu                sync.Mutex
}

// ValidateECHVersions enforces the client version policy before sending an offer.
func (c *HandshakeConfig) ValidateECHVersions() error {
	if c.ECHConfigList != nil && ((c.MinVersion != 0 && c.MinVersion != protocol.Version1_3) || (c.MaxVersion != 0 && c.MaxVersion != protocol.Version1_3)) {
		return fmt.Errorf("ECH requires DTLS 1.3: %w", dtlserrors.ErrUnsupportedProtocolVersion)
	}

	return nil
}

// GenerateConnectionID returns a CID matching the configured receive length.
func (c *HandshakeConfig) GenerateConnectionID() ([]byte, error) {
	cid := c.ConnectionIDGenerator()
	if len(cid) != c.ReceiveCIDLength {
		return nil, fmt.Errorf("%w: generator returned %d bytes, want %d", dtlserrors.ErrInvalidConnectionIDLength, len(cid), c.ReceiveCIDLength)
	}

	return cid, nil
}

// Timer is the timer surface used by the handshake state machines.
type Timer interface {
	C() <-chan time.Time
	Stop()
}

type systemTimer struct {
	timer *time.Timer
}

func (t *systemTimer) C() <-chan time.Time {
	return t.timer.C
}

func (t *systemTimer) Stop() {
	t.timer.Stop()
}

// NewTimer returns a handshake timer.
func (c *HandshakeConfig) NewTimer(d time.Duration) Timer {
	if c.TimerFactory != nil {
		return c.TimerFactory(d)
	}

	return &systemTimer{timer: time.NewTimer(d)}
}

func (c *HandshakeConfig) WriteKeyLog(label string, clientRandom, secret []byte) {
	if c.KeyLogWriter == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := fmt.Fprintf(c.KeyLogWriter, "%s %x %x\n", label, clientRandom, secret)
	if err != nil {
		c.Log.Debugf("failed to write key log file: %s", err)
	}
}

func (c *HandshakeConfig) setNameToCertificateLocked() {
	nameToCertificate := make(map[string]*tls.Certificate)
	for i := range c.LocalCertificates {
		cert := &c.LocalCertificates[i]
		x509Cert := cert.Leaf
		if x509Cert == nil {
			var parseErr error
			x509Cert, parseErr = x509.ParseCertificate(cert.Certificate[0])
			if parseErr != nil {
				continue
			}
		}
		if len(x509Cert.Subject.CommonName) > 0 {
			nameToCertificate[strings.ToLower(x509Cert.Subject.CommonName)] = cert
		}
		for _, san := range x509Cert.DNSNames {
			nameToCertificate[strings.ToLower(san)] = cert
		}
	}
	c.nameToCertificate = nameToCertificate
}

func (c *HandshakeConfig) GetCertificate(clientHelloInfo *ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.shouldGetCertificateFromCallbackLocked(clientHelloInfo) {
		cert, err := c.LocalGetCertificate(clientHelloInfo)
		if cert != nil || err != nil {
			return cert, err
		}
	}

	if c.nameToCertificate == nil {
		c.setNameToCertificateLocked()
	}

	if len(c.LocalCertificates) == 0 {
		return nil, dtlserrors.ErrNoCertificates
	}

	if len(c.LocalCertificates) == 1 {
		return &c.LocalCertificates[0], nil
	}

	if len(clientHelloInfo.ServerName) == 0 {
		return &c.LocalCertificates[0], nil
	}

	if cert := c.getCertificateForNameLocked(clientHelloInfo.ServerName); cert != nil {
		return cert, nil
	}

	return &c.LocalCertificates[0], nil
}

func (c *HandshakeConfig) shouldGetCertificateFromCallbackLocked(clientHelloInfo *ClientHelloInfo) bool {
	if c.LocalGetCertificate == nil {
		return false
	}

	return len(c.LocalCertificates) == 0 || len(clientHelloInfo.ServerName) > 0
}

func (c *HandshakeConfig) getCertificateForNameLocked(serverName string) *tls.Certificate {
	name := strings.TrimRight(strings.ToLower(serverName), ".")

	if cert, ok := c.nameToCertificate[name]; ok {
		return cert
	}

	// A certificate wildcard replaces only the left-most DNS label.
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		candidate := "*" + name[dot:]
		if cert, ok := c.nameToCertificate[candidate]; ok {
			return cert
		}
	}

	return nil
}

func (c *HandshakeConfig) GetClientCertificate(cri *CertificateRequestInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.LocalGetClientCertificate != nil {
		return c.LocalGetClientCertificate(cri)
	}

	for i := range c.LocalCertificates {
		chain := c.LocalCertificates[i]
		if err := cri.SupportsCertificate(&chain); err != nil {
			continue
		}

		return &chain, nil
	}

	return new(tls.Certificate), nil
}

// SendServerName omits IP literals from SNI while retaining them for verification.
func (c *HandshakeConfig) SendServerName() bool {
	return len(c.ServerName) > 0 && net.ParseIP(c.ServerName) == nil
}

func FilterCipherSuitesForCertificate(
	cert *tls.Certificate,
	cipherSuites []cryptosuite.Suite,
) []cryptosuite.Suite {
	if cert == nil || cert.PrivateKey == nil {
		return cipherSuites
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return cipherSuites
	}

	var certType clientcertificate.Type
	switch signer.Public().(type) {
	case ed25519.PublicKey, *ecdsa.PublicKey:
		certType = clientcertificate.ECDSASign
	case *rsa.PublicKey:
		certType = clientcertificate.RSASign
	}

	return slices.DeleteFunc(slices.Clone(cipherSuites), func(suite cryptosuite.Suite) bool {
		return !suite.Capabilities().SupportsVersion(protocol.Version1_3) && suite.AuthenticationType() == cryptosuite.AuthenticationTypeCertificate && certType != suite.CertificateType()
	})
}

// UsableSession rejects legacy sessions and sessions belonging to another role.
//
//nolint:cyclop // Check role, negotiated parameters, and current authentication policy.
func (c *HandshakeConfig) UsableSession(session internalstate.Session, isClient bool) bool {
	if session.Ticket != nil || session.Version != 1 || session.IsClient != isClient || len(session.ID) == 0 || len(session.Secret) != 48 {
		return false
	}
	if c.ExtendedMasterSecret == RequireExtendedMasterSecret && !session.ExtendedMasterSecret {
		return false
	}
	if c.ExtendedMasterSecret == DisableExtendedMasterSecret && session.ExtendedMasterSecret {
		return false
	}
	var suite CipherSuite
	for _, candidate := range c.LocalCipherSuites {
		if candidate.ID() == session.CipherSuiteID {
			suite = candidate

			break
		}
	}
	if suite == nil {
		return false
	}
	if suite.AuthenticationType() == cryptosuite.AuthenticationTypePreSharedKey {
		return c.usableSessionPSK(session, isClient)
	}
	if isClient {
		if len(session.PeerCertificates) == 0 {
			return false
		}
		chains, err := c.verifySessionCertificate(session.PeerCertificates)
		if err != nil {
			return false
		}

		return c.VerifyPeerCertificate == nil || c.VerifyPeerCertificate(session.PeerCertificates, chains) == nil
	}

	return c.ClientAuth == NoClientCert || c.ClientAuth == RequestClientCert
}

func (c *HandshakeConfig) verifySessionCertificate(raw [][]byte) ([][]*x509.Certificate, error) {
	if c.InsecureSkipVerify {
		return nil, nil
	} //nolint:nilnil // Verification was explicitly disabled.
	algs := c.LocalCertSignatureSchemes
	if len(algs) == 0 {
		algs = c.LocalSignatureSchemes
	}

	return dtlscrypto.VerifyServerCert(raw, c.RootCAs, c.ServerName, algs)
}

// VerifyResumedConnection applies current authentication policy after Finished.
func (c *HandshakeConfig) VerifyResumedConnection(state *internalstate.State12) error {
	if state.IsClient && state.CipherSuite.AuthenticationType() == cryptosuite.AuthenticationTypeCertificate {
		if _, err := c.verifySessionCertificate(state.PeerCertificates); err != nil {
			return err
		}
	}
	if c.VerifyConnection != nil {
		return c.VerifyConnection(state)
	}

	return nil
}

func (c *HandshakeConfig) usableSessionPSK(session internalstate.Session, isClient bool) bool {
	var key []byte
	var err error
	if isClient {
		if c.LocalPSKCallback == nil {
			return false
		}
		key, err = c.LocalPSKCallback(bytes.Clone(session.IdentityHint))
	} else {
		if c.SelectPSK == nil {
			return false
		}
		_, key, _, err = c.SelectPSK([][]byte{bytes.Clone(session.IdentityHint)})
	}

	return err == nil && len(key) > 0 && sha256.Sum256(key) == session.PSKHash
}
