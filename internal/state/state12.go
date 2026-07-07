// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

// State12 holds state that is meaningful only for DTLS 1.2.
type State12 struct {
	*Common

	PreMasterSecret []byte
	MasterSecret    []byte

	ExtendedMasterSecret        bool
	RemoteSupportsRenegotiation bool

	NamedCurve   elliptic.Curve
	LocalKeypair *elliptic.Keypair

	Cookie                []byte
	HandshakeSendSequence int
	HandshakeRecvSequence int

	RemoteCertRequestAlgs      []signaturehash.Algorithm
	RemoteSignatureSchemes     []signaturehash.Algorithm // signature_algorithms from peer
	RemoteCertSignatureSchemes []signaturehash.Algorithm // signature_algorithms_cert from peer

	RemoteRequestedCertificate bool
	LocalCertificatesVerify    []byte
	LocalVerifyData            []byte
	LocalKeySignature          []byte

	PeerCertificatesVerified bool
}

func (s *State12) InitCipherSuite() error {
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
