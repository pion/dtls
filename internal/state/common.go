// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package state holds the internal DTLS connection state used during and after
// the handshake.
package state

import (
	"bytes"
	"sync/atomic"

	"github.com/pion/dtls/v3/internal/negotiation"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/transport/v4/replaydetector"
)

// Common is the protocol-independent connection state shared by DTLS versions.
type Common struct {
	localEpoch, remoteEpoch   atomic.Uint32
	LocalSequenceNumber       []uint64 // uint48
	RemoteSequenceNumber      []uint64
	LocalRandom, RemoteRandom handshake.Random
	CipherSuite               cryptosuite.Suite // nil if a cipherSuite hasn't been chosen
	PeerCertificates          [][]byte
	IdentityHint              []byte
	SessionID                 []byte
	NegotiatedProtocol        string

	srtpProtectionProfile         atomic.Uint32 // Negotiated SRTPProtectionProfile
	RemoteSRTPMasterKeyIdentifier []byte

	// Connection Identifiers must be negotiated afresh on session resumption.
	// https://datatracker.ietf.org/doc/html/rfc9146#name-the-connection_id-extension

	// LocalConnectionID is the locally generated connection ID that is expected
	// to be received from the remote endpoint.
	// For a server, this is the connection ID sent in ServerHello.
	// For a client, this is the connection ID sent in the ClientHello.
	localConnectionID atomic.Value
	// LocalCIDOffered reports whether the local endpoint sent a connection_id
	// extension.
	LocalCIDOffered bool
	// RemoteConnectionID is the connection ID that the remote endpoint
	// specifies should be sent.
	// For a server, this is the connection ID received in the ClientHello.
	// For a client, this is the connection ID received in the ServerHello.
	RemoteConnectionID []byte
	// RemoteCIDOffered reports whether the peer sent a connection_id
	// extension.
	RemoteCIDOffered bool
	// RRCNegotiated reports whether both peers exchanged the RFC 9853
	// extension. The negotiation is shared by DTLS 1.2 and DTLS 1.3.
	RRCNegotiated bool
	// pendingLocalConnectionID is the uncommitted CID offered by this client.
	pendingLocalConnectionID atomic.Pointer[[]byte]

	IsClient bool

	ServerName string

	ReplayDetector []replaydetector.ReplayDetector

	PeerSupportedProtocols []string

	// LocalVersion is the DTLS version we intend to speak on this connection.
	LocalVersion protocol.Version
	// RemoteVersions are the DTLS versions advertised by the peer.
	RemoteVersions []protocol.Version

	// ClientHello snapshots are transient negotiation state.
	// they aren't serialized with resumable connection state.
	LocalClientHelloSnapshots  negotiation.ClientHelloSnapshots
	RemoteClientHelloSnapshots negotiation.ClientHelloSnapshots
}

func (s *Common) RemoteEpoch() uint16 {
	return uint16(s.remoteEpoch.Load()) //nolint:gosec // Epochs are stored as uint16 values.
}

func (s *Common) SetRemoteEpoch(epoch uint16) {
	s.remoteEpoch.Store(uint32(epoch))
}

func (s *Common) LocalEpoch() uint16 {
	return uint16(s.localEpoch.Load()) //nolint:gosec // Epochs are stored as uint16 values.
}

func (s *Common) SetLocalEpoch(epoch uint16) {
	s.localEpoch.Store(uint32(epoch))
}

func (s *Common) SetSRTPProtectionProfile(profile extension.SRTPProtectionProfile) {
	s.srtpProtectionProfile.Store(uint32(profile))
}

func (s *Common) SRTPProtectionProfile() extension.SRTPProtectionProfile {
	return extension.SRTPProtectionProfile(s.srtpProtectionProfile.Load()) //nolint:gosec // Stored profile is uint16.
}

func (s *Common) LocalConnectionID() []byte {
	if val, ok := s.localConnectionID.Load().([]byte); ok {
		return val
	}

	return nil
}

func (s *Common) SetLocalConnectionID(v []byte) {
	s.localConnectionID.Store(v)
}

// RecordLocalClientHello retains an offer and publishes its pending CID.
func (s *Common) RecordLocalClientHello(snapshot negotiation.ClientHelloSnapshot) error {
	if err := s.LocalClientHelloSnapshots.Record(snapshot); err != nil {
		return err
	}
	if cid, offered := negotiation.ConnectionIDOffer(snapshot); offered {
		s.pendingLocalConnectionID.Store(&cid)
	} else {
		s.pendingLocalConnectionID.Store(nil)
	}

	return nil
}

// ResetConnectionIDs clears committed CID state and starts a new decision.
func (s *Common) ResetConnectionIDs() {
	s.SetLocalConnectionID(nil)
	s.RemoteConnectionID, s.LocalCIDOffered, s.RemoteCIDOffered = nil, false, false
	s.RRCNegotiated = false
	s.pendingLocalConnectionID.Store(nil)
}

// CommitNegotiatedExtensions applies a fully validated extension decision.
func (s *Common) CommitNegotiatedExtensions(decision *negotiation.ConnectionID) {
	if decision == nil {
		s.ResetConnectionIDs()

		return
	}

	localCID, remoteCID := decision.ServerCID, decision.ClientCID
	if s.IsClient {
		localCID, remoteCID = remoteCID, localCID
	}
	s.SetLocalConnectionID(bytes.Clone(localCID))
	s.RemoteConnectionID = bytes.Clone(remoteCID)
	s.LocalCIDOffered, s.RemoteCIDOffered = true, true
	s.RRCNegotiated = decision.ReturnRoutabilityCheck
	s.pendingLocalConnectionID.Store(nil)
}

// LocalConnectionIDForInboundRecords returns the negotiated CID, or the
// pending wire offer while a client is still waiting for ServerHello.
func (s *Common) LocalConnectionIDForInboundRecords() []byte {
	if cid := s.pendingLocalConnectionID.Load(); s.IsClient && cid != nil {
		return *cid
	}

	return s.LocalConnectionID()
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
		TrafficKeys:   &TrafficKeyState{},
	}
}
