// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"encoding/gob"
	"sync/atomic"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	dtlsutil "github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// State holds the dtls connection state and implements both encoding.BinaryMarshaler and
// encoding.BinaryUnmarshaler.
type State struct {
	localEpoch, remoteEpoch   uint16
	localRandom, remoteRandom handshake.Random
	masterSecret              []byte
	sequenceNumber            uint64
	srtpProtectionProfile     SRTPProtectionProfile
	localConnectionID         []byte
	remoteConnectionID        []byte
	isClient                  bool
	version                   protocol.Version

	CipherSuiteID      CipherSuiteID
	PeerCertificates   [][]byte
	IdentityHint       []byte
	SessionID          []byte
	NegotiatedProtocol string
}

type serializedState struct {
	Version               protocol.Version
	LocalEpoch            uint16
	RemoteEpoch           uint16
	LocalRandom           [handshake.RandomLength]byte
	RemoteRandom          [handshake.RandomLength]byte
	CipherSuiteID         uint16
	MasterSecret          []byte
	SequenceNumber        uint64
	SRTPProtectionProfile uint16
	PeerCertificates      [][]byte
	IdentityHint          []byte
	SessionID             []byte
	LocalConnectionID     []byte
	RemoteConnectionID    []byte
	IsClient              bool
	NegotiatedProtocol    string
}

func generateState(internalState *dtlsstate.State) (*State, error) {
	if internalState.CipherSuite == nil {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}
	if internalState.LocalVersion.Equal(protocol.Version1_3) {
		return nil, ErrStateSerializationUnsupported
	}

	epoch := internalState.GetLocalEpoch()

	return &State{
		localEpoch:            internalState.GetLocalEpoch(),
		remoteEpoch:           internalState.GetRemoteEpoch(),
		localRandom:           internalState.LocalRandom,
		remoteRandom:          internalState.RemoteRandom,
		masterSecret:          internalState.MasterSecret,
		sequenceNumber:        atomic.LoadUint64(&internalState.LocalSequenceNumber[epoch]),
		srtpProtectionProfile: internalState.GetSRTPProtectionProfile(),
		localConnectionID:     internalState.GetLocalConnectionID(),
		remoteConnectionID:    internalState.RemoteConnectionID,
		isClient:              internalState.IsClient,
		version:               protocol.Version1_2,
		CipherSuiteID:         internalState.CipherSuite.ID(),
		PeerCertificates:      internalState.PeerCertificates,
		IdentityHint:          internalState.IdentityHint,
		SessionID:             internalState.SessionID,
		NegotiatedProtocol:    internalState.NegotiatedProtocol,
	}, nil
}

func generateStateForVerifyConnection(active dtlsstate.Active) (*State, error) {
	switch state := active.(type) {
	case *dtlsstate.State:
		return generateState(state)
	case *dtlsstate.State13:
		return generateState13(state)
	default:
		return nil, dtlserrors.ErrInvalidProtocolVersionState
	}
}

func generateState13(internalState *dtlsstate.State13) (*State, error) {
	if internalState.CipherSuite == nil {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}

	common := internalState.CommonFields()
	if common == nil {
		return nil, dtlserrors.ErrInvalidProtocolVersionState
	}

	epoch := common.GetLocalEpoch()
	var sequenceNumber uint64
	if int(epoch) < len(common.LocalSequenceNumber) {
		sequenceNumber = atomic.LoadUint64(&common.LocalSequenceNumber[epoch])
	}

	return &State{
		localEpoch:            common.GetLocalEpoch(),
		remoteEpoch:           common.GetRemoteEpoch(),
		localRandom:           common.LocalRandom,
		remoteRandom:          common.RemoteRandom,
		sequenceNumber:        sequenceNumber,
		srtpProtectionProfile: common.GetSRTPProtectionProfile(),
		localConnectionID:     bytes.Clone(common.GetLocalConnectionID()),
		remoteConnectionID:    bytes.Clone(common.RemoteConnectionID),
		isClient:              common.IsClient,
		version:               protocol.Version1_3,
		CipherSuiteID:         internalState.CipherSuite.ID(),
		PeerCertificates:      dtlsutil.CloneByteSlices(common.PeerCertificates),
		IdentityHint:          bytes.Clone(common.IdentityHint),
		SessionID:             bytes.Clone(common.SessionID),
		NegotiatedProtocol:    common.NegotiatedProtocol,
	}, nil
}

func (s *State) serialize() (*serializedState, error) {
	// 0 (TLS_NULL_WITH_NULL_NULL) is never negotiated, so it signals an unset suite.
	if s.CipherSuiteID == 0 {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}
	if s.version.Equal(protocol.Version1_3) {
		return nil, ErrStateSerializationUnsupported
	}

	version := s.version
	if version.Equal(protocol.Version{}) {
		version = protocol.Version1_2
	}

	return &serializedState{
		Version:               version,
		LocalEpoch:            s.localEpoch,
		RemoteEpoch:           s.remoteEpoch,
		CipherSuiteID:         uint16(s.CipherSuiteID),
		MasterSecret:          s.masterSecret,
		SequenceNumber:        s.sequenceNumber,
		LocalRandom:           s.localRandom.MarshalFixed(),
		RemoteRandom:          s.remoteRandom.MarshalFixed(),
		SRTPProtectionProfile: uint16(s.srtpProtectionProfile),
		PeerCertificates:      s.PeerCertificates,
		IdentityHint:          s.IdentityHint,
		SessionID:             s.SessionID,
		LocalConnectionID:     s.localConnectionID,
		RemoteConnectionID:    s.remoteConnectionID,
		IsClient:              s.isClient,
		NegotiatedProtocol:    s.NegotiatedProtocol,
	}, nil
}

func (s *State) deserialize(serialized serializedState) {
	s.version = serialized.Version
	if s.version.Equal(protocol.Version{}) {
		s.version = protocol.Version1_2
	}
	s.localEpoch = serialized.LocalEpoch
	s.remoteEpoch = serialized.RemoteEpoch
	s.localRandom.UnmarshalFixed(serialized.LocalRandom)
	s.remoteRandom.UnmarshalFixed(serialized.RemoteRandom)
	s.masterSecret = serialized.MasterSecret
	s.sequenceNumber = serialized.SequenceNumber
	s.srtpProtectionProfile = SRTPProtectionProfile(serialized.SRTPProtectionProfile)
	s.localConnectionID = serialized.LocalConnectionID
	s.remoteConnectionID = serialized.RemoteConnectionID
	s.isClient = serialized.IsClient

	s.CipherSuiteID = CipherSuiteID(serialized.CipherSuiteID)
	s.PeerCertificates = serialized.PeerCertificates
	s.IdentityHint = serialized.IdentityHint
	s.SessionID = serialized.SessionID
	s.NegotiatedProtocol = serialized.NegotiatedProtocol
}

func (s *State) initializedCipherSuite() (CipherSuite, error) {
	cipherSuite := cipherSuiteForID(s.CipherSuiteID)
	if cipherSuite == nil {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}
	if cipherSuite.IsInitialized() {
		return cipherSuite, nil
	}

	localRandom := s.localRandom.MarshalFixed()
	remoteRandom := s.remoteRandom.MarshalFixed()

	var err error
	if s.isClient {
		err = cipherSuite.Init(s.masterSecret, localRandom[:], remoteRandom[:], true)
	} else {
		err = cipherSuite.Init(s.masterSecret, remoteRandom[:], localRandom[:], false)
	}
	if err != nil {
		return nil, err
	}

	return cipherSuite, nil
}

// generateInternalState is the inverse of generateState: it expands the public
// State into the internal state used by the connection internals.
func (s *State) generateInternalState() (*dtlsstate.State, error) {
	if s.CipherSuiteID == 0 {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}
	if s.version.Equal(protocol.Version1_3) {
		return nil, ErrStateSerializationUnsupported
	}

	state := &dtlsstate.State{
		Common: &dtlsstate.Common{
			LocalRandom:        s.localRandom,
			RemoteRandom:       s.remoteRandom,
			CipherSuite:        cipherSuiteForID(s.CipherSuiteID),
			RemoteConnectionID: s.remoteConnectionID,
			IsClient:           s.isClient,
			PeerCertificates:   s.PeerCertificates,
			IdentityHint:       s.IdentityHint,
			SessionID:          s.SessionID,
			NegotiatedProtocol: s.NegotiatedProtocol,
			LocalVersion:       protocol.Version1_2,
		},
		MasterSecret: s.masterSecret,
	}
	state.LocalEpoch.Store(s.localEpoch)
	state.RemoteEpoch.Store(s.remoteEpoch)
	state.SetSRTPProtectionProfile(s.srtpProtectionProfile)
	state.SetLocalConnectionID(s.localConnectionID)

	for len(state.LocalSequenceNumber) <= int(s.localEpoch) {
		state.LocalSequenceNumber = append(state.LocalSequenceNumber, uint64(0))
	}
	atomic.StoreUint64(&state.LocalSequenceNumber[s.localEpoch], s.sequenceNumber)

	if err := state.InitCipherSuite(); err != nil {
		return nil, err
	}

	return state, nil
}

// MarshalBinary is a binary.BinaryMarshaler.MarshalBinary implementation.
func (s *State) MarshalBinary() ([]byte, error) {
	serialized, err := s.serialize()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(*serialized); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary is a binary.BinaryUnmarshaler.UnmarshalBinary implementation.
func (s *State) UnmarshalBinary(data []byte) error {
	enc := gob.NewDecoder(bytes.NewBuffer(data))
	var serialized serializedState
	if err := enc.Decode(&serialized); err != nil {
		return err
	}
	if serialized.Version.Equal(protocol.Version1_3) {
		return ErrStateSerializationUnsupported
	}

	s.deserialize(serialized)

	_, err := s.initializedCipherSuite()

	return err
}

// ExportKeyingMaterial returns length bytes of exported key material in a new
// slice as defined in RFC 5705.
// This allows protocols to use DTLS for key establishment, but
// then use some of the keying material for their own purposes.
func (s *State) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	if s.localEpoch == 0 {
		return nil, dtlserrors.ErrHandshakeInProgress
	} else if len(context) != 0 {
		return nil, dtlserrors.ErrContextUnsupported
	} else if _, ok := invalidKeyingLabels()[label]; ok {
		return nil, dtlserrors.ErrReservedExportKeyingMaterial
	}
	cipherSuite, err := s.initializedCipherSuite()
	if err != nil {
		return nil, err
	}

	localRandom := s.localRandom.MarshalFixed()
	remoteRandom := s.remoteRandom.MarshalFixed()

	seed := []byte(label)
	if s.isClient {
		seed = append(append(seed, localRandom[:]...), remoteRandom[:]...)
	} else {
		seed = append(append(seed, remoteRandom[:]...), localRandom[:]...)
	}

	return prf.PHash(s.masterSecret, seed, length, cipherSuite.HashFunc())
}

// RemoteRandomBytes returns the remote client hello random bytes.
func (s *State) RemoteRandomBytes() [handshake.RandomBytesLength]byte {
	return s.remoteRandom.RandomBytes
}
