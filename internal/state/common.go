// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package state holds the internal DTLS connection state used during and after
// the handshake.
package state

import (
	"sync/atomic"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/transport/v4/replaydetector"
)

// Common is the protocol-independent connection state shared by DTLS versions.
type Common struct {
	LocalEpoch, RemoteEpoch   atomic.Value
	LocalSequenceNumber       []uint64 // uint48
	RemoteSequenceNumber      []uint64
	LocalRandom, RemoteRandom handshake.Random
	CipherSuite               ciphersuite.CipherSuite // nil if a cipherSuite hasn't been chosen
	PeerCertificates          [][]byte
	IdentityHint              []byte
	SessionID                 []byte
	NegotiatedProtocol        string

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

	ServerName string

	ReplayDetector []replaydetector.ReplayDetector

	PeerSupportedProtocols []string

	// LocalVersion is the DTLS version we intend to speak on this connection.
	LocalVersion protocol.Version
	// RemoteVersions are the DTLS versions advertised by the peer.
	RemoteVersions []protocol.Version
}

func (s *Common) GetRemoteEpoch() uint16 {
	if remoteEpoch, ok := s.RemoteEpoch.Load().(uint16); ok {
		return remoteEpoch
	}

	return 0
}

func (s *Common) GetLocalEpoch() uint16 {
	if localEpoch, ok := s.LocalEpoch.Load().(uint16); ok {
		return localEpoch
	}

	return 0
}

func (s *Common) SetSRTPProtectionProfile(profile extension.SRTPProtectionProfile) {
	s.SRTPProtectionProfile.Store(profile)
}

func (s *Common) GetSRTPProtectionProfile() extension.SRTPProtectionProfile {
	if val, ok := s.SRTPProtectionProfile.Load().(extension.SRTPProtectionProfile); ok {
		return val
	}

	return 0
}

func (s *Common) GetLocalConnectionID() []byte {
	if val, ok := s.LocalConnectionID.Load().([]byte); ok {
		return val
	}

	return nil
}

func (s *Common) SetLocalConnectionID(v []byte) {
	s.LocalConnectionID.Store(v)
}

// State is retained as the DTLS 1.2 state alias for callers that still only
// support DTLS 1.2 resumption/state serialization.
type State = State12

// CommonFields returns the embedded common state.
func (s *State12) CommonFields() *Common {
	if s == nil {
		return nil
	}

	return s.Common
}

// CommonFields returns the embedded common state.
func (s *State13) CommonFields() *Common {
	if s == nil {
		return nil
	}

	return s.Common
}

// NewState12 creates DTLS 1.2 state with initialized common fields.
func NewState12(isClient bool) State12 {
	common := &Common{
		IsClient:     isClient,
		LocalVersion: protocol.Version1_2,
	}

	return State12{
		Common: common,
	}
}

// NewState13 creates DTLS 1.3 state with initialized common fields.
func NewState13(isClient bool) State13 {
	common := &Common{
		IsClient:     isClient,
		LocalVersion: protocol.Version1_3,
	}

	return State13{
		Common:        common,
		LocalKeypairs: make(map[elliptic.Curve]*elliptic.Keypair),
	}
}
