// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"sync/atomic"

	dtlsciphersuite "github.com/pion/dtls/v4/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/util"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

// State12 holds state that is meaningful only for DTLS 1.2.
type State12 struct {
	HandshakeComplete  atomic.Bool
	RemoteReplayCutoff uint64
	*Common
	Protection cryptosuite.Protection
	usage      trafficUsage

	PreMasterSecret   []byte
	MasterSecret      []byte
	ResumeSession     *Session
	PSKHash           [sha256.Size]byte
	ServerCertificate *tls.Certificate

	ExtendedMasterSecret        bool
	RemoteSupportsRenegotiation bool

	NamedCurve   elliptic.Curve
	LocalKeypair *elliptic.Keypair

	Cookie                []byte
	HasHelloVerifyRequest bool
	HandshakeSendSequence int
	HandshakeRecvSequence int

	RemoteCertRequestAlgs      []signaturehash.Algorithm
	RemoteSignatureSchemes     []signaturehash.Algorithm // signature_algorithms from peer
	RemoteCertSignatureSchemes []signaturehash.Algorithm // signature_algorithms_cert from peer

	RemoteRequestedCertificate bool
	LocalCertificatesVerify    []byte
	LocalVerifyData            []byte
	LocalKeySignature          []byte

	ClientKeyExchange        *handshake.MessageClientKeyExchange
	ClientFlightProcessed    bool
	PeerCertificatesVerified bool

	remoteServerKeyExchange *handshake.MessageServerKeyExchange
}

// SetRemoteServerKeyExchange retains the parsed server key exchange for the
// remainder of the handshake.
func (s *State12) SetRemoteServerKeyExchange(message *handshake.MessageServerKeyExchange) {
	s.remoteServerKeyExchange = message
}

// RemoteServerKeyExchange returns the parsed server key exchange.
func (s *State12) RemoteServerKeyExchange() *handshake.MessageServerKeyExchange {
	return s.remoteServerKeyExchange
}

// ShouldWrapConnectionID reports whether outgoing DTLS 1.2 records should
// use CID record encoding.
func (s *State12) ShouldWrapConnectionID() bool {
	return len(s.RemoteConnectionID) > 0
}

func (s *State12) InitCipherSuite() error {
	if s.CipherSuite == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}
	if s.Protection != nil {
		return nil
	}

	localRandom := s.LocalRandom.MarshalFixed()
	remoteRandom := s.RemoteRandom.MarshalFixed()

	role := cryptosuite.EndpointRoleServer
	if s.IsClient {
		role = cryptosuite.EndpointRoleClient
	}
	clientRandom, serverRandom := remoteRandom[:], localRandom[:]
	if s.IsClient {
		clientRandom, serverRandom = localRandom[:], remoteRandom[:]
	}
	material, err := dtlsciphersuite.NewKeyMaterial(s.MasterSecret, clientRandom, serverRandom, role)
	if err != nil {
		return err
	}
	factory, ok := s.CipherSuite.(cryptosuite.ConnectionSuite)
	if !ok {
		return dtlserrors.ErrInvalidCipherSuite
	}
	protection, err := factory.NewConnectionProtection(material)
	if err != nil {
		return err
	}
	if protection == nil {
		return dtlserrors.ErrInvalidCipherSuite
	}
	s.Protection = protection

	return nil
}

// Seal counts successful encryption under the DTLS 1.2 write key.
func (s *State12) Seal(record cryptosuite.Record, plaintext []byte) ([]byte, error) {
	return s.usage.seal(s.Protection, record, plaintext)
}

// Open counts authentication failures under the DTLS 1.2 read key.
func (s *State12) Open(record cryptosuite.Record, protected []byte) ([]byte, error) {
	return s.usage.open(s.Protection, record, protected)
}

// Usage returns successful seals and authentication failures for the key pair.
func (s *State12) Usage() (sealed, failed uint64) { return s.usage.counts() }

// RestoreUsage restores counters before an imported connection starts processing records.
func (s *State12) RestoreUsage(sealed, failed uint64) {
	s.usage.sealed.Store(sealed)
	s.usage.failed.Store(failed)
}

// Session stores authenticated resumption metadata for either protocol version.
type Session struct {
	ID                   []byte
	Secret               []byte //nolint:gosec // Session stores intentionally retain the resumption secret.
	Ticket               *SessionTicket
	Version              uint8
	IsClient             bool
	CipherSuiteID        cryptosuite.ID
	ExtendedMasterSecret bool
	PeerCertificates     [][]byte
	IdentityHint         []byte
	PSKHash              [sha256.Size]byte
}

// Session snapshots the authenticated DTLS 1.2 session.
func (s *State12) Session() Session {
	return Session{
		ID: bytes.Clone(s.SessionID), Secret: bytes.Clone(s.MasterSecret),
		Version: 1, IsClient: s.IsClient, CipherSuiteID: s.CipherSuite.ID(),
		ExtendedMasterSecret: s.ExtendedMasterSecret, PeerCertificates: util.CloneByteSlices(s.PeerCertificates),
		IdentityHint: bytes.Clone(s.IdentityHint), PSKHash: s.PSKHash,
	}
}
