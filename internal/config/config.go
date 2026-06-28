// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package config holds the internal DTLS configuration shared between the
// public package and the handshake internals.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/logging"
)

// ClientAuthType declares the internal client authentication policy.
type ClientAuthType int

// ExtendedMasterSecretType declares the internal extended master secret policy.
type ExtendedMasterSecretType int

// Config is the internal configuration structure.
type Config struct {
	Certificates                  []tls.Certificate
	CipherSuites                  []ciphersuite.ID
	SignatureSchemes              []tls.SignatureScheme
	CertificateSignatureSchemes   []tls.SignatureScheme
	SRTPProtectionProfiles        []extension.SRTPProtectionProfile
	SRTPMasterKeyIdentifier       []byte
	ClientAuth                    ClientAuthType
	ExtendedMasterSecret          ExtendedMasterSecretType
	FlightInterval                time.Duration
	DisableRetransmitBackoff      bool
	PSKIdentityHint               []byte
	InsecureSkipVerify            bool
	InsecureHashes                bool
	VerifyPeerCertificate         func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	RootCAs                       *x509.CertPool
	ClientCAs                     *x509.CertPool
	ServerName                    string
	LoggerFactory                 logging.LoggerFactory
	MTU                           int
	ReplayProtectionWindow        int
	KeyLogWriter                  io.Writer
	SupportedProtocols            []string
	EllipticCurves                []elliptic.Curve
	InsecureSkipVerifyHello       bool
	ConnectionIDGenerator         func() []byte
	PaddingLengthGenerator        func(uint) uint
	HelloRandomBytesGenerator     func() [handshake.RandomBytesLength]byte
	ClientHelloMessageHook        func(handshake.MessageClientHello) handshake.Message
	ServerHelloMessageHook        func(handshake.MessageServerHello) handshake.Message
	CertificateRequestMessageHook func(handshake.MessageCertificateRequest) handshake.Message
	OnConnectionAttempt           func(net.Addr) error
	ListenConfig                  net.ListenConfig
	MinVersion                    protocol.Version
	MaxVersion                    protocol.Version
}
