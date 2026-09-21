// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"encoding/gob"
	"math"

	"github.com/pion/dtls/v4/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	dtlsutil "github.com/pion/dtls/v4/internal/util"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v4/pkg/crypto/prf"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

// State holds the dtls connection state and implements both encoding.BinaryMarshaler and
// encoding.BinaryUnmarshaler.
type State struct {
	localEpoch, remoteEpoch   uint64
	localRandom, remoteRandom handshake.Random
	masterSecret              []byte
	cipherSuiteDescriptor     cryptosuite.Suite
	sequenceNumber            uint64
	srtpProtectionProfile     SRTPProtectionProfile
	peerSRTPMKI               []byte
	localConnectionID         []byte
	remoteConnectionID        []byte
	rrcNegotiated             bool
	isClient                  bool
	version                   protocol.Version

	CipherSuiteID      cryptosuite.ID
	PeerCertificates   [][]byte
	IdentityHint       []byte
	SessionID          []byte
	NegotiatedProtocol string
	// KeyUsage is the current record keys' usage.
	KeyUsage *KeyUsageStats
	// exporterMasterSecret is the DTLS 1.3 exporter_master_secret
	// (RFC 8446 section 7.5, inherited by RFC 9147). It is only populated for a
	// DTLS 1.3 connection and is consumed by ExportKeyingMaterial. It is not
	// serialized (DTLS 1.3 state serialization is unsupported). The hash used to
	// derive from it comes from cipherSuiteDescriptor.
	exporterMasterSecret []byte
}

// KeyUsageStats reports usage of the current directional record keys.
// It excludes older keys retained for retransmissions. Counters restart for
// each new key. DTLS 1.3 connections can use Conn.UpdateKeys to rotate keys.
// Recommendations are advisory and do not affect the connection.
type KeyUsageStats struct {
	WriteEpoch             uint64
	ReadEpoch              uint64
	SealedRecords          uint64
	AuthenticationFailures uint64
	RecommendedLimits      cryptosuite.UsageLimits
	// Remaining counts are zero when unspecified or at/above the recommendation.
	RemainingSealedRecords          uint64
	RemainingAuthenticationFailures uint64
}

func keyUsageStats(state *dtlsstate.State13) *KeyUsageStats {
	if state.TrafficKeys == nil || state.CipherSuite == nil {
		return nil
	}
	write, hasWrite := state.TrafficKeys.CurrentWrite()
	read, hasRead := state.TrafficKeys.CurrentRead()
	if !hasWrite || !hasRead {
		return nil
	}
	sealed, _ := write.Usage()
	_, failed := read.Usage()

	return newKeyUsageStats(state.CipherSuite, write.Epoch, read.Epoch, sealed, failed)
}

func newKeyUsageStats(suite cryptosuite.Suite, writeEpoch, readEpoch, sealed, failed uint64) *KeyUsageStats {
	var limits cryptosuite.UsageLimits
	if provider, ok := suite.(cryptosuite.UsageLimitProvider); ok {
		limits = provider.UsageLimits()
	}

	return &KeyUsageStats{
		WriteEpoch: writeEpoch, ReadEpoch: readEpoch,
		SealedRecords: sealed, AuthenticationFailures: failed,
		RecommendedLimits:               limits,
		RemainingSealedRecords:          remainingUsage(limits.MaxSealedRecords, sealed),
		RemainingAuthenticationFailures: remainingUsage(limits.MaxAuthenticationFailures, failed),
	}
}

func keyUsageStats12(state *dtlsstate.State12) *KeyUsageStats {
	if state.Protection == nil {
		return nil
	}
	sealed, failed := state.Usage()

	return newKeyUsageStats(state.CipherSuite, state.LocalEpoch(), state.RemoteEpoch(), sealed, failed)
}

func remainingUsage(limit, used uint64) uint64 {
	if used >= limit {
		return 0
	}

	return limit - used
}

type serializedState struct {
	KeyUsage              *KeyUsageStats
	Version               protocol.Version
	LocalEpoch            uint16
	RemoteEpoch           uint16
	LocalRandom           [handshake.RandomLength]byte
	RemoteRandom          [handshake.RandomLength]byte
	CipherSuiteID         uint16
	MasterSecret          []byte
	SequenceNumber        uint64
	SRTPProtectionProfile uint16
	PeerSRTPMKI           []byte
	PeerCertificates      [][]byte
	IdentityHint          []byte
	SessionID             []byte
	LocalConnectionID     []byte
	RemoteConnectionID    []byte
	RRCNegotiated         bool
	IsClient              bool
	NegotiatedProtocol    string
}

func generateState(internalState *dtlsstate.State) (*State, error) {
	if internalState.CipherSuite == nil {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}
	if internalState.LocalVersion == protocol.Version1_3 {
		return nil, ErrStateSerializationUnsupported
	}

	epoch := internalState.LocalEpoch()
	profile := internalState.SRTPProtectionProfile()
	var peerMKI []byte
	if profile != 0 {
		peerMKI = bytes.Clone(internalState.RemoteSRTPMasterKeyIdentifier)
	}

	return &State{
		KeyUsage:              keyUsageStats12(internalState),
		localEpoch:            internalState.LocalEpoch(),
		remoteEpoch:           internalState.RemoteEpoch(),
		localRandom:           internalState.LocalRandom,
		remoteRandom:          internalState.RemoteRandom,
		masterSecret:          internalState.MasterSecret,
		sequenceNumber:        internalState.NextLocalSequenceNumber(epoch),
		srtpProtectionProfile: profile,
		peerSRTPMKI:           peerMKI,
		localConnectionID:     internalState.LocalConnectionID(),
		remoteConnectionID:    internalState.RemoteConnectionID,
		rrcNegotiated:         internalState.RRCNegotiated,
		isClient:              internalState.IsClient,
		version:               protocol.Version1_2,
		CipherSuiteID:         internalState.CipherSuite.ID(),
		cipherSuiteDescriptor: internalState.CipherSuite,
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

	epoch := common.LocalEpoch()
	sequenceNumber := common.NextLocalSequenceNumber(epoch)

	return &State{
		localEpoch:            common.LocalEpoch(),
		remoteEpoch:           common.RemoteEpoch(),
		localRandom:           common.LocalRandom,
		remoteRandom:          common.RemoteRandom,
		sequenceNumber:        sequenceNumber,
		srtpProtectionProfile: common.SRTPProtectionProfile(),
		localConnectionID:     bytes.Clone(common.LocalConnectionID()),
		remoteConnectionID:    bytes.Clone(common.RemoteConnectionID),
		rrcNegotiated:         common.RRCNegotiated,
		isClient:              common.IsClient,
		version:               protocol.Version1_3,
		CipherSuiteID:         internalState.CipherSuite.ID(),
		cipherSuiteDescriptor: internalState.CipherSuite,
		PeerCertificates:      dtlsutil.CloneByteSlices(common.PeerCertificates),
		KeyUsage:              keyUsageStats(internalState),
		IdentityHint:          bytes.Clone(common.IdentityHint),
		SessionID:             bytes.Clone(common.SessionID),
		NegotiatedProtocol:    common.NegotiatedProtocol,
		exporterMasterSecret:  bytes.Clone(internalState.KeySchedule.ExporterMasterSecret),
	}, nil
}

// NegotiatedVersion returns the DTLS version negotiated for this connection.
func (s *State) NegotiatedVersion() protocol.Version {
	return s.version
}

// Role indicates which side of the DTLS handshake an endpoint took.
type Role uint8

const (
	// RoleUnknown is the zero value, used when the role is not yet resolved.
	RoleUnknown Role = iota
	// RoleClient is the endpoint that sends the ClientHello.
	RoleClient
	// RoleServer is the endpoint that answers with the ServerHello.
	RoleServer
)

// Role reports which side of the handshake the local endpoint took.
func (s *State) Role() Role {
	if s.isClient {
		return RoleClient
	}

	return RoleServer
}

func (s *State) serialize() (*serializedState, error) {
	// 0 (TLS_NULL_WITH_NULL_NULL) is never negotiated, so it signals an unset suite.
	if s.CipherSuiteID == 0 {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}
	if s.version == protocol.Version1_3 {
		return nil, ErrStateSerializationUnsupported
	}
	if s.localEpoch > math.MaxUint16 || s.remoteEpoch > math.MaxUint16 {
		return nil, dtlserrors.ErrEpochOverflow
	}

	version := s.version
	if version == 0 {
		version = protocol.Version1_2
	}

	return &serializedState{
		KeyUsage:              s.KeyUsage,
		Version:               version,
		LocalEpoch:            uint16(s.localEpoch),  //nolint:gosec // Checked before serialization.
		RemoteEpoch:           uint16(s.remoteEpoch), //nolint:gosec // Checked before serialization.
		CipherSuiteID:         uint16(s.CipherSuiteID),
		MasterSecret:          s.masterSecret,
		SequenceNumber:        s.sequenceNumber,
		LocalRandom:           s.localRandom.MarshalFixed(),
		RemoteRandom:          s.remoteRandom.MarshalFixed(),
		SRTPProtectionProfile: uint16(s.srtpProtectionProfile),
		PeerSRTPMKI:           bytes.Clone(s.peerSRTPMKI),
		PeerCertificates:      s.PeerCertificates,
		IdentityHint:          s.IdentityHint,
		SessionID:             s.SessionID,
		LocalConnectionID:     s.localConnectionID,
		RemoteConnectionID:    s.remoteConnectionID,
		RRCNegotiated:         s.rrcNegotiated,
		IsClient:              s.isClient,
		NegotiatedProtocol:    s.NegotiatedProtocol,
	}, nil
}

func (s *State) deserialize(serialized serializedState) {
	s.KeyUsage = serialized.KeyUsage
	s.cipherSuiteDescriptor = nil
	s.version = serialized.Version
	if s.version == 0 {
		s.version = protocol.Version1_2
	}
	s.localEpoch = uint64(serialized.LocalEpoch)
	s.remoteEpoch = uint64(serialized.RemoteEpoch)
	s.localRandom.UnmarshalFixed(serialized.LocalRandom)
	s.remoteRandom.UnmarshalFixed(serialized.RemoteRandom)
	s.masterSecret = serialized.MasterSecret
	s.sequenceNumber = serialized.SequenceNumber
	s.srtpProtectionProfile = SRTPProtectionProfile(serialized.SRTPProtectionProfile)
	s.peerSRTPMKI = bytes.Clone(serialized.PeerSRTPMKI)
	s.localConnectionID = serialized.LocalConnectionID
	s.remoteConnectionID = serialized.RemoteConnectionID
	s.rrcNegotiated = serialized.RRCNegotiated
	s.isClient = serialized.IsClient

	s.CipherSuiteID = cryptosuite.ID(serialized.CipherSuiteID)
	s.PeerCertificates = serialized.PeerCertificates
	s.IdentityHint = serialized.IdentityHint
	s.SessionID = serialized.SessionID
	s.NegotiatedProtocol = serialized.NegotiatedProtocol
}

func (s *State) cipherSuite() (cryptosuite.Suite, error) {
	cipherSuite := s.cipherSuiteDescriptor
	if cipherSuite == nil {
		cipherSuite = nil
	} else if cipherSuite.ID() != s.CipherSuiteID {
		return nil, dtlserrors.ErrInvalidCipherSuite
	}
	if cipherSuite == nil {
		cipherSuite = ciphersuite.ForID(s.CipherSuiteID)
	}
	if cipherSuite == nil {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}
	if err := validateCipherSuite(cipherSuite); err != nil {
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
	if s.version == protocol.Version1_3 {
		return nil, ErrStateSerializationUnsupported
	}
	if s.localEpoch > math.MaxUint16 || s.remoteEpoch > math.MaxUint16 {
		return nil, dtlserrors.ErrEpochOverflow
	}

	cipherSuite, err := s.cipherSuite()
	if err != nil {
		return nil, err
	}
	if !cipherSuite.Capabilities().SupportsVersion(protocol.Version1_2) {
		return nil, dtlserrors.ErrInvalidCipherSuite
	}

	state := &dtlsstate.State{
		Common: &dtlsstate.Common{
			LocalRandom:        s.localRandom,
			RemoteRandom:       s.remoteRandom,
			CipherSuite:        cipherSuite,
			RemoteConnectionID: s.remoteConnectionID,
			RRCNegotiated:      s.rrcNegotiated,
			IsClient:           s.isClient,
			PeerCertificates:   s.PeerCertificates,
			IdentityHint:       s.IdentityHint,
			SessionID:          s.SessionID,
			NegotiatedProtocol: s.NegotiatedProtocol,
			LocalVersion:       protocol.Version1_2,
		},
		MasterSecret: s.masterSecret,
	}
	state.SetLocalEpoch(s.localEpoch)
	state.SetRemoteEpoch(s.remoteEpoch)
	state.RemoteSRTPMasterKeyIdentifier = bytes.Clone(s.peerSRTPMKI)
	state.SetSRTPProtectionProfile(s.srtpProtectionProfile)
	state.SetLocalConnectionID(s.localConnectionID)

	state.SetLocalSequenceNumber(s.localEpoch, s.sequenceNumber)
	if s.KeyUsage != nil {
		state.RestoreUsage(s.KeyUsage.SealedRecords, s.KeyUsage.AuthenticationFailures)
	}

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
	if serialized.Version == protocol.Version1_3 {
		return ErrStateSerializationUnsupported
	}

	s.deserialize(serialized)
	if s.CipherSuiteID == 0 {
		return dtlserrors.ErrCipherSuiteNotSet
	}
	if len(s.masterSecret) == 0 {
		return dtlserrors.ErrInvalidProtectionInput
	}
	if cipherSuite := ciphersuite.ForID(s.CipherSuiteID); cipherSuite != nil && (!cipherSuite.Capabilities().SupportsVersion(protocol.Version1_2) || validateCipherSuite(cipherSuite) != nil) {
		return dtlserrors.ErrInvalidCipherSuite
	}

	return nil
}

// ExportKeyingMaterial returns length bytes of exported key material in a new
// slice as defined in RFC 5705.
// This allows protocols to use DTLS for key establishment, but
// then use some of the keying material for their own purposes.
func (s *State) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	if s.localEpoch == 0 {
		return nil, dtlserrors.ErrHandshakeInProgress
	}

	// DTLS 1.3 derives exported keying material with the HKDF-based TLS 1.3
	// exporter (RFC 8446 section 7.5, inherited by RFC 9147); DTLS 1.2 uses the
	// legacy TLS 1.2 PRF (RFC 5705). Note DTLS version numbers decrease as the
	// version increases (1.2 = 0xfefd, 1.3 = 0xfefc), so this is an exact-version
	// dispatch, not an ordered comparison.
	if s.version == protocol.Version1_3 {
		return s.exportKeyingMaterialHKDF(label, context, length)
	}

	if len(context) != 0 {
		return nil, dtlserrors.ErrContextUnsupported
	} else if _, ok := invalidKeyingLabels()[label]; ok {
		return nil, dtlserrors.ErrReservedExportKeyingMaterial
	}

	return s.exportKeyingMaterialPRF(label, length)
}

// exportKeyingMaterialPRF implements the TLS 1.2 PRF keying-material exporter
// (RFC 5705), used by DTLS 1.2: PRF(master_secret, label, client_random +
// server_random). The randoms are ordered client-then-server, so the seed is
// role-dependent.
func (s *State) exportKeyingMaterialPRF(label string, length int) ([]byte, error) {
	cipherSuite, err := s.cipherSuite()
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

// exportKeyingMaterialHKDF implements the HKDF-based TLS 1.3 exporter (RFC 8446
// section 7.5), as used by DTLS 1.3 (RFC 9147). For a given label and context it
// computes:
//
//	Derive-Secret(exporter_master_secret, label, "")             -> secret
//	HKDF-Expand-Label(secret, "exporter", Hash(context), length) -> keying material
//
// HKDF-Expand-Label uses RFC 9147 section 5.9's "dtls13" label prefix (applied
// by the keyschedule package). Unlike the DTLS 1.2 PRF path, the exporter output
// does not depend on the endpoint role or the handshake randoms.
func (s *State) exportKeyingMaterialHKDF(label string, context []byte, length int) ([]byte, error) {
	if len(s.exporterMasterSecret) == 0 {
		return nil, dtlserrors.ErrHandshakeInProgress
	}
	cipherSuite, err := s.cipherSuite()
	if err != nil {
		return nil, err
	}
	hashFunc := cipherSuite.HashFunc()

	// Derive-Secret(Secret, Label, "") is HKDF-Expand-Label(Secret, Label,
	// Hash(""), Hash.length); DeriveSecret hashes an empty transcript when nil.
	exporterSecret, err := keyschedule.DeriveSecret(hashFunc, s.exporterMasterSecret, label, nil)
	if err != nil {
		return nil, err
	}

	h := hashFunc()
	if _, err := h.Write(context); err != nil {
		return nil, err
	}

	return keyschedule.HkdfExpandLabel(hashFunc, exporterSecret, "exporter", h.Sum(nil), length)
}

// RemoteRandomBytes returns the remote client hello random bytes.
func (s *State) RemoteRandomBytes() [handshake.RandomBytesLength]byte {
	return s.remoteRandom.RandomBytes
}
