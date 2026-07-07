// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package state holds the internal DTLS connection state used during and after
// the handshake.
package state

import (
	"sync/atomic"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/transport/v4/replaydetector"
)

type HandshakeTrafficSecrets13 struct {
	Client []byte
	Server []byte
}

type State struct {
	LocalEpoch, RemoteEpoch   atomic.Value
	LocalSequenceNumber       []uint64 // uint48
	RemoteSequenceNumber      []uint64
	LocalRandom, RemoteRandom handshake.Random
	MasterSecret              []byte
	CipherSuite               ciphersuite.CipherSuite // nil if a cipherSuite hasn't been chosen
	PeerCertificates          [][]byte
	IdentityHint              []byte
	SessionID                 []byte
	NegotiatedProtocol        string

	RemoteSupportsRenegotiation bool // True when Client Hello contained renegotiation extension

	SRTPProtectionProfile         atomic.Value // Negotiated SRTPProtectionProfile
	RemoteSRTPMasterKeyIdentifier []byte

	// Connection Identifiers must be negotiated afresh on session resumption.
	// https://datatracker.ietf.org/doc/html/rfc9146#name-the-connection_id-extension

	// LocalConnectionID is the locally generated connection ID that is expected
	// to be received from the remote endpoint.
	// For a server, this is the connection ID sent in ServerHello.
	// For a client, this is the connection ID sent in the ClientHello.
	LocalConnectionID atomic.Value
	// RemoteConnectionID is the connection ID that the remote endpoint
	// specifies should be sent.
	// For a server, this is the connection ID received in the ClientHello.
	// For a client, this is the connection ID received in the ServerHello.
	RemoteConnectionID []byte

	IsClient bool

	PreMasterSecret      []byte
	ExtendedMasterSecret bool

	NamedCurve                 elliptic.Curve
	LocalKeypair               *elliptic.Keypair
	Cookie                     []byte
	HandshakeSendSequence      int
	HandshakeRecvSequence      int
	ServerName                 string
	RemoteCertRequestAlgs      []signaturehash.Algorithm
	RemoteSignatureSchemes     []signaturehash.Algorithm // signature_algorithms from peer
	RemoteCertSignatureSchemes []signaturehash.Algorithm // signature_algorithms_cert from peer
	RemoteRequestedCertificate bool                      // Did we get a CertificateRequest
	LocalCertificatesVerify    []byte                    // cache CertificateVerify
	LocalVerifyData            []byte                    // cached VerifyData
	LocalKeySignature          []byte                    // cached keySignature
	PeerCertificatesVerified   bool

	ReplayDetector []replaydetector.ReplayDetector

	PeerSupportedProtocols []string

	// LocalVersion is the DTLS version we intend to speak on this connection.
	LocalVersion protocol.Version
	// RemoteVersions are the DTLS versions advertised by the peer
	RemoteVersions []protocol.Version
	// HandshakeTrafficSecrets13 are derived from the ECDHE secret and the
	// transcript through ServerHello. Record protection consumes them later.
	HandshakeTrafficSecrets13 HandshakeTrafficSecrets13
	// LocalKeyEntries are the DTLS 1.3 KeyShareEntry values generated locally
	// and sent in the ClientHello's key_share extension.
	LocalKeyEntries []extension.KeyShareEntry
	// LocalKeypairs are the DTLS 1.3 keypairs backing localKeyEntries, indexed
	// by group so the selected ServerHello key_share can recover its private key.
	LocalKeypairs    map[elliptic.Curve]*elliptic.Keypair
	RemoteKeyEntries *[]extension.KeyShareEntry
	RemoteGroups     []elliptic.Curve
}

func (s *State) InitCipherSuite() error {
	if s.CipherSuite == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}
	if s.CipherSuite.IsInitialized() {
		return nil
	}

	localRandom := s.LocalRandom.MarshalFixed()
	remoteRandom := s.RemoteRandom.MarshalFixed()

	var err error
	if s.IsClient {
		err = s.CipherSuite.Init(s.MasterSecret, localRandom[:], remoteRandom[:], true)
	} else {
		err = s.CipherSuite.Init(s.MasterSecret, remoteRandom[:], localRandom[:], false)
	}
	if err != nil {
		return err
	}

	return nil
}

func (s *State) GetRemoteEpoch() uint16 {
	if remoteEpoch, ok := s.RemoteEpoch.Load().(uint16); ok {
		return remoteEpoch
	}

	return 0
}

func (s *State) GetLocalEpoch() uint16 {
	if localEpoch, ok := s.LocalEpoch.Load().(uint16); ok {
		return localEpoch
	}

	return 0
}

func (s *State) SetSRTPProtectionProfile(profile extension.SRTPProtectionProfile) {
	s.SRTPProtectionProfile.Store(profile)
}

func (s *State) GetSRTPProtectionProfile() extension.SRTPProtectionProfile {
	if val, ok := s.SRTPProtectionProfile.Load().(extension.SRTPProtectionProfile); ok {
		return val
	}

	return 0
}

func (s *State) GetLocalConnectionID() []byte {
	if val, ok := s.LocalConnectionID.Load().([]byte); ok {
		return val
	}

	return nil
}

func (s *State) SetLocalConnectionID(v []byte) {
	s.LocalConnectionID.Store(v)
}
