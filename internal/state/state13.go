// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

type TrafficSecrets struct {
	Client []byte
	Server []byte
}

// HandshakeTrafficSecrets is retained as a type alias for tests and helper
// code that name the DTLS 1.3 handshake traffic secrets directly.
type HandshakeTrafficSecrets = TrafficSecrets

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

// State13 holds state that is meaningful only for DTLS 1.3.
type State13 struct {
	*Common

	KeySchedule KeySchedule

	// KeyAgreementSecret is the ECDHE or hybrid shared secret that feeds the
	// TLS 1.3 HKDF key schedule.
	KeyAgreementSecret []byte

	SelectedGroup elliptic.Curve

	LocalKeypair  *elliptic.Keypair
	LocalKeypairs map[elliptic.Curve]*elliptic.Keypair

	LocalKeyEntries []extension.KeyShareEntry

	RemoteKeyEntries *[]extension.KeyShareEntry
	RemoteGroups     []elliptic.Curve

	Cookie                []byte
	HandshakeSendSequence int
	HandshakeRecvSequence int

	RemoteSignatureSchemes     []signaturehash.Algorithm // signature_algorithms from peer
	RemoteCertSignatureSchemes []signaturehash.Algorithm // signature_algorithms_cert from peer
}
