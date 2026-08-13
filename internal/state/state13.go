// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"bytes"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
)

type TrafficSecrets struct {
	Client []byte
	Server []byte
}

type KeySchedule struct {
	EarlySecret     []byte
	HandshakeSecret []byte

	// MasterSecret is TLS/DTLS 1.3's key-schedule master secret, not the
	// DTLS 1.2 PRF master_secret.
	MasterSecret []byte

	HandshakeTraffic TrafficSecrets

	ClientApplicationTrafficSecret0 []byte
	ServerApplicationTrafficSecret0 []byte

	ExporterMasterSecret   []byte
	ResumptionMasterSecret []byte
}

// CIDState holds connection ID state negotiated for DTLS 1.3. RFC 9147
// reuses the connection_id extension [1] and its directional semantics from
// RFC 9146, Section 3 [2], and defines the DTLS 1.3 record encoding and CID
// update messages in Sections 4.3 [3].
//
// Each endpoint advertises the CID it wants to receive:
// Receive describes locally generated CIDs carried by the peer,
// while Send describes	peer-generated CIDs carried by this endpoint.
// A present, zero-length connection_id extension still negotiates CID support,
// but disables CIDs in that direction.
// Negotiated must not be inferred from either
// CID length. [4]
//
// The initial CID values remain in Common so a dual-stack ClientHello can be
// handed to DTLS 1.2 without losing its offer. The directional state here is
// separate because an active DTLS 1.3 CID can later change through the
// messages defined by RFC 9147, Section 9 [1].
//
// 1. https://datatracker.ietf.org/doc/html/rfc9147#section-9
// 2. https://datatracker.ietf.org/doc/html/rfc9146.html#section-3
// 3. https://datatracker.ietf.org/doc/html/rfc9147#section-4
// 4. https://datatracker.ietf.org/doc/html/rfc9146.html#section-3
type CIDState struct {
	// Negotiated reports whether the connection_id extension was negotiated,
	// including when one or both endpoints advertised a zero-length CID.
	Negotiated bool
	// Receive controls parsing and updating CIDs carried by the peer.
	Receive CIDReceiveState
	// Send controls encoding and updating CIDs carried by this endpoint.
	Send CIDSendState
}

// CIDReceiveState describes locally generated CIDs carried in protected
// records sent by the peer.
type CIDReceiveState struct {
	// Expected reports whether records from the peer must set the C bit in the
	// DTLS 1.3 unified header and carry a CID.
	Expected bool
	// Length is the number of CID bytes to parse after the C bit. DTLS 1.3
	// records do not encode this lengt
	Length int
	// CanSendNewConnectionID reports whether this endpoint may send
	// NewConnectionID. RFC 9147, Section 9 forbids that message when this
	// endpoint negotiated receiving an empty CID.
	CanSendNewConnectionID bool
}

// CIDSendState describes peer-generated CIDs carried in protected records
// sent by this endpoint.
type CIDSendState struct {
	// UseCID reports whether records sent to the peer must set the C bit in the
	// DTLS 1.3 unified header and carry Active.
	UseCID bool
	// Active is the peer-provided CID currently used for outgoing records. It
	// may diverge from Common.RemoteConnectionID after NewConnectionID.
	Active []byte
}

// State13 holds state that is meaningful only for DTLS 1.3.
type State13 struct {
	*Common

	CID         CIDState
	KeySchedule KeySchedule
	TrafficKeys *TrafficKeyState

	// KeyAgreementSecret is the ECDHE or hybrid shared secret that feeds the
	// TLS 1.3 HKDF key schedule.
	KeyAgreementSecret []byte

	SelectedGroup elliptic.Curve

	LocalKeypair  *elliptic.Keypair
	LocalKeypairs map[elliptic.Curve]*elliptic.Keypair

	LocalKeyEntries []extension13.KeyShareEntry

	RemoteKeyEntries    []extension13.KeyShareEntry
	HasRemoteKeyEntries bool
	RemoteGroups        []elliptic.Curve

	Cookie                []byte
	HandshakeSendSequence int
	HandshakeRecvSequence int

	RemoteSignatureSchemes     []signaturehash.Algorithm // signature_algorithms from peer
	RemoteCertSignatureSchemes []signaturehash.Algorithm // signature_algorithms_cert from peer
}

// ShouldWrapConnectionID reports whether outgoing records should use the
// legacy DTLS 1.2 CID record encoding.
func (*State13) ShouldWrapConnectionID() bool {
	return false
}

// ResetConnectionIDs clears the connection IDs and CID state.
func (s *State13) ResetConnectionIDs() {
	s.SetLocalConnectionID(nil)
	s.LocalCIDOffered = false
	s.RemoteConnectionID = nil
	s.RemoteCIDOffered = false
	s.CID = CIDState{}
}

// NegotiateConnectionIDs records the connection IDs negotiated.
func (s *State13) NegotiateConnectionIDs(remoteCID []byte) {
	localCID := bytes.Clone(s.LocalConnectionID())

	s.SetLocalConnectionID(localCID)
	s.LocalCIDOffered = true
	s.RemoteConnectionID = bytes.Clone(remoteCID)
	s.RemoteCIDOffered = true
	s.CID = CIDState{
		Negotiated: true,
		Receive: CIDReceiveState{
			Expected:               len(localCID) > 0,
			Length:                 len(localCID),
			CanSendNewConnectionID: len(localCID) > 0,
		},
		Send: CIDSendState{
			UseCID: len(remoteCID) > 0,
			Active: bytes.Clone(remoteCID),
		},
	}
}
