// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package config contains internal handshake configuration.
package config

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	internalstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
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
	CipherSuite           = ciphersuite.CipherSuite
	CipherSuiteID         = ciphersuite.ID
	SRTPProtectionProfile = extension.SRTPProtectionProfile
)

type ClientHelloInfo struct {
	ServerName   string
	CipherSuites []CipherSuiteID
	RandomBytes  [handshake.RandomBytesLength]byte
}

type CertificateRequestInfo struct {
	AcceptableCAs [][]byte
}

func (cri *CertificateRequestInfo) SupportsCertificate(c *tls.Certificate) error {
	return SupportsCertificate(cri.AcceptableCAs, c)
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
	VerifyConnection              func(*internalstate.State) error
	HasSessionStore               bool
	GetSession                    func(key []byte) (id, secret []byte, err error)
	SetSession                    func(key, id, secret []byte) error
	DelSession                    func(key []byte) error
	RootCAs                       *x509.CertPool
	ClientCAs                     *x509.CertPool
	InitialRetransmitInterval     time.Duration
	DisableRetransmitBackoff      bool
	CustomCipherSuites            func() []CipherSuite
	EllipticCurves                []elliptic.Curve
	InsecureSkipHelloVerify       bool
	ConnectionIDGenerator         func() []byte
	HelloRandomBytesGenerator     func() [handshake.RandomBytesLength]byte
	OnFlightState                 func(flight, state uint8)
	Log                           logging.LeveledLogger
	KeyLogWriter                  io.Writer
	LocalGetCertificate           func(*ClientHelloInfo) (*tls.Certificate, error)
	LocalGetClientCertificate     func(*CertificateRequestInfo) (*tls.Certificate, error)
	InitialEpoch                  uint16
	ClientHelloMessageHook        func(handshake.MessageClientHello) handshake.Message
	ServerHelloMessageHook        func(handshake.MessageServerHello) handshake.Message
	CertificateRequestMessageHook func(handshake.MessageCertificateRequest) handshake.Message
	ResumeState                   *internalstate.State
	MinVersion                    protocol.Version
	MaxVersion                    protocol.Version
	OnFlightState13               func(flight, state uint8)

	nameToCertificate map[string]*tls.Certificate
	mu                sync.Mutex
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

	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
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

func SupportedVersionsRange(minVersion, maxVersion protocol.Version) []protocol.Version {
	ordered := []protocol.Version{protocol.Version1_3, protocol.Version1_2}
	out := make([]protocol.Version, 0, len(ordered))
	for _, v := range ordered {
		if versionAtLeast(v, minVersion) && versionAtMost(v, maxVersion) {
			out = append(out, v)
		}
	}

	return out
}

func versionAtLeast(v, lo protocol.Version) bool {
	// DTLS encodes newer versions as numerically smaller Minor bytes
	return v.Minor <= lo.Minor
}

func versionAtMost(v, hi protocol.Version) bool {
	return v.Minor >= hi.Minor
}
