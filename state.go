// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"encoding/gob"
	"math"

	"github.com/pion/dtls/v4/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight13 "github.com/pion/dtls/v4/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	dtlsutil "github.com/pion/dtls/v4/internal/util"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v4/pkg/crypto/prf"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
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
	// exporterMasterSecret is exporter_master_secret from
	// https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1.
	exporterMasterSecret []byte
	state13              *serializedState13
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
	DTLS13                *serializedState13
	ExporterMasterSecret  []byte
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

func generateState(active dtlsstate.Active) (*State, error) {
	if active == nil || active.CommonFields() == nil {
		return nil, dtlserrors.ErrInvalidProtocolVersionState
	}
	common := active.CommonFields()
	if common.CipherSuite == nil {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}
	state := snapshotCommonState(common)
	switch internalState := active.(type) {
	case *dtlsstate.State:
		if common.LocalVersion == protocol.Version1_3 {
			return nil, dtlserrors.ErrInvalidProtocolVersionState
		}
		state.version = protocol.Version1_2
		state.KeyUsage = keyUsageStats12(internalState)
		state.masterSecret = bytes.Clone(internalState.MasterSecret)
	case *dtlsstate.State13:
		state.version = protocol.Version1_3
		state.KeyUsage = keyUsageStats(internalState)
		state.exporterMasterSecret = bytes.Clone(internalState.KeySchedule.ExporterMasterSecret)
	default:
		return nil, dtlserrors.ErrInvalidProtocolVersionState
	}

	return state, nil
}

func snapshotCommonState(common *dtlsstate.Common) *State {
	return &State{
		localEpoch:            common.LocalEpoch(),
		remoteEpoch:           common.RemoteEpoch(),
		localRandom:           common.LocalRandom,
		remoteRandom:          common.RemoteRandom,
		sequenceNumber:        common.NextLocalSequenceNumber(common.LocalEpoch()),
		srtpProtectionProfile: common.SRTPProtectionProfile(),
		peerSRTPMKI:           bytes.Clone(common.RemoteSRTPMasterKeyIdentifier),
		localConnectionID:     bytes.Clone(common.LocalConnectionID()),
		remoteConnectionID:    bytes.Clone(common.RemoteConnectionID),
		rrcNegotiated:         common.RRCNegotiated,
		isClient:              common.IsClient,
		CipherSuiteID:         common.CipherSuite.ID(),
		cipherSuiteDescriptor: common.CipherSuite,
		PeerCertificates:      dtlsutil.CloneByteSlices(common.PeerCertificates),
		IdentityHint:          bytes.Clone(common.IdentityHint),
		SessionID:             bytes.Clone(common.SessionID),
		NegotiatedProtocol:    common.NegotiatedProtocol,
	}
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
	localEpoch, remoteEpoch := s.localEpoch, s.remoteEpoch
	if s.version == protocol.Version1_3 {
		suite, err := s.cipherSuite()
		if err != nil {
			return nil, err
		}
		if err = s.validate13(suite); err != nil {
			return nil, err
		}
		localEpoch, remoteEpoch = 0, 0
	} else if s.localEpoch > math.MaxUint16 || s.remoteEpoch > math.MaxUint16 {
		return nil, dtlserrors.ErrEpochOverflow
	}

	version := s.version
	if version == 0 {
		version = protocol.Version1_2
	}

	return &serializedState{
		DTLS13:                s.state13,
		ExporterMasterSecret:  s.exporterMasterSecret,
		KeyUsage:              s.KeyUsage,
		Version:               version,
		LocalEpoch:            uint16(localEpoch),  //nolint:gosec // Checked before serialization.
		RemoteEpoch:           uint16(remoteEpoch), //nolint:gosec // Checked before serialization.
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
	s.state13 = serialized.DTLS13
	s.exporterMasterSecret = bytes.Clone(serialized.ExporterMasterSecret)
	s.KeyUsage = serialized.KeyUsage
	s.cipherSuiteDescriptor = nil
	s.version = serialized.Version
	if s.version == 0 {
		s.version = protocol.Version1_2
	}
	s.localEpoch = uint64(serialized.LocalEpoch)
	s.remoteEpoch = uint64(serialized.RemoteEpoch)
	if s.version == protocol.Version1_3 && s.state13 != nil {
		if len(s.state13.Write) > 0 {
			s.localEpoch = s.state13.Write[len(s.state13.Write)-1].Epoch
		}
		if len(s.state13.Read) > 0 {
			s.remoteEpoch = s.state13.Read[len(s.state13.Read)-1].Epoch
		}
	}
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
	if cipherSuite != nil && cipherSuite.ID() != s.CipherSuiteID {
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
func (s *State) generateInternalState() (dtlsstate.Active, error) {
	if s.CipherSuiteID == 0 {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}
	if s.version != protocol.Version1_3 && (s.localEpoch > math.MaxUint16 || s.remoteEpoch > math.MaxUint16) {
		return nil, dtlserrors.ErrEpochOverflow
	}

	cipherSuite, err := s.cipherSuite()
	if err != nil {
		return nil, err
	}
	if s.version == protocol.Version1_3 {
		return s.generateInternalState13(cipherSuite)
	}
	if !cipherSuite.Capabilities().SupportsVersion(protocol.Version1_2) {
		return nil, dtlserrors.ErrInvalidCipherSuite
	}

	state := &dtlsstate.State{Common: s.restoreCommonState(cipherSuite, protocol.Version1_2), MasterSecret: bytes.Clone(s.masterSecret)}
	if s.KeyUsage != nil {
		state.RestoreUsage(s.KeyUsage.SealedRecords, s.KeyUsage.AuthenticationFailures)
	}

	if err := state.InitCipherSuite(); err != nil {
		return nil, err
	}

	return state, nil
}

func (s *State) restoreCommonState(suite cryptosuite.Suite, version protocol.Version) *dtlsstate.Common {
	common := &dtlsstate.Common{
		LocalRandom: s.localRandom, RemoteRandom: s.remoteRandom,
		CipherSuite: suite, IsClient: s.isClient, LocalVersion: version,
		PeerCertificates: dtlsutil.CloneByteSlices(s.PeerCertificates),
		IdentityHint:     bytes.Clone(s.IdentityHint), SessionID: bytes.Clone(s.SessionID),
		NegotiatedProtocol: s.NegotiatedProtocol, RRCNegotiated: s.rrcNegotiated,
		RemoteConnectionID:            bytes.Clone(s.remoteConnectionID),
		RemoteSRTPMasterKeyIdentifier: bytes.Clone(s.peerSRTPMKI),
	}
	common.SetLocalEpoch(s.localEpoch)
	common.SetRemoteEpoch(s.remoteEpoch)
	common.SetLocalConnectionID(bytes.Clone(s.localConnectionID))
	common.SetSRTPProtectionProfile(s.srtpProtectionProfile)
	common.SetLocalSequenceNumber(s.localEpoch, s.sequenceNumber)

	return common
}

// Application traffic keys survive DTLS 1.3 restoration.
type serializedState13 struct {
	Write, Read            []serializedTrafficGeneration
	ResumptionMasterSecret []byte
	HandshakeSendSequence  int
	HandshakeRecvSequence  int
	CIDNegotiated          bool
	ReceiveIDs             [][]byte
	Send                   dtlsstate.CIDSendState
}

type serializedTrafficGeneration struct {
	Epoch, Generation            uint64
	Secret                       []byte
	SequenceNumber               uint64
	SequenceNumberSeen           bool
	SealedRecords, FailedRecords uint64
}

func snapshotState13(state *dtlsstate.State13) *serializedState13 {
	if state.TrafficKeys == nil {
		return nil
	}
	write, read := state.TrafficKeys.Generations()
	sendSequence, receiveSequence := state.HandshakeSequences()

	return &serializedState13{
		Write:                  snapshotTrafficGenerations(state.Common, write, true),
		Read:                   snapshotTrafficGenerations(state.Common, read, false),
		ResumptionMasterSecret: bytes.Clone(state.KeySchedule.ResumptionMasterSecret),
		HandshakeSendSequence:  sendSequence,
		HandshakeRecvSequence:  receiveSequence,
		CIDNegotiated:          state.CID.Negotiated,
		ReceiveIDs:             state.CID.Receive.IDs.Values(),
		Send:                   state.CID.Send.Clone(),
	}
}

func snapshotTrafficGenerations(common *dtlsstate.Common, generations []*dtlsstate.TrafficGeneration, write bool) []serializedTrafficGeneration {
	var snapshots []serializedTrafficGeneration
	for _, generation := range generations {
		if generation == nil || generation.Epoch < dtlsflight13.EpochApplication {
			continue
		}
		sequence, seen := common.HighestRemoteSequenceNumber(generation.Epoch)
		if write {
			sequence, seen = common.NextLocalSequenceNumber(generation.Epoch), true
		}
		sealed, failed := generation.Usage()
		snapshots = append(snapshots, serializedTrafficGeneration{
			Epoch: generation.Epoch, Generation: generation.Generation,
			Secret: bytes.Clone(generation.Secret), SequenceNumber: sequence, SequenceNumberSeen: seen,
			SealedRecords: sealed, FailedRecords: failed,
		})
	}

	return snapshots
}

func (s *State) validate13(suite cryptosuite.Suite) error {
	snapshot := s.state13
	if snapshot == nil || len(snapshot.Write) == 0 || len(snapshot.Read) == 0 {
		return dtlserrors.ErrHandshakeInProgress
	}
	if !suite.Capabilities().SupportsVersion(protocol.Version1_3) {
		return dtlserrors.ErrInvalidCipherSuite
	}
	secretSize := suite.HashFunc()().Size()
	if len(s.exporterMasterSecret) != secretSize || !snapshot.validKeySchedule(secretSize) {
		return dtlserrors.ErrInvalidProtectionInput
	}
	if err := validateTrafficGenerations(snapshot.Write, secretSize, recordlayer.MaxSequenceNumber+1); err != nil {
		return err
	}
	if err := validateTrafficGenerations(snapshot.Read, secretSize, recordlayer.MaxSequenceNumber); err != nil {
		return err
	}

	return snapshot.validateConnectionIDs(len(s.localConnectionID))
}

func (snapshot *serializedState13) validKeySchedule(secretSize int) bool {
	return (len(snapshot.ResumptionMasterSecret) == 0 || len(snapshot.ResumptionMasterSecret) == secretSize) &&
		snapshot.HandshakeSendSequence >= 0 && snapshot.HandshakeRecvSequence >= 0
}

func (snapshot *serializedState13) validateConnectionIDs(localLength int) error {
	if localLength > 255 || len(snapshot.Send.Active) > 255 ||
		snapshot.Send.UseCID != (len(snapshot.Send.Active) != 0) ||
		!validConnectionIDs(snapshot.ReceiveIDs, localLength, localLength) ||
		!validConnectionIDs(snapshot.Send.Spares, 1, 255) {
		return dtlserrors.ErrInvalidProtectionInput
	}

	return nil
}

func validConnectionIDs(ids [][]byte, minLength, maxLength int) bool {
	if len(ids) > dtlsstate.MaxConnectionIDs {
		return false
	}
	for _, id := range ids {
		if len(id) == 0 || len(id) < minLength || len(id) > maxLength {
			return false
		}
	}

	return true
}

func validateTrafficGenerations(generations []serializedTrafficGeneration, secretSize int, maxSequence uint64) error {
	seen := make(map[uint64]bool, len(generations))
	currentEpoch := generations[len(generations)-1].Epoch
	for _, generation := range generations {
		if generation.Epoch < dtlsflight13.EpochApplication || generation.Epoch > currentEpoch ||
			seen[generation.Epoch] || generation.Generation != generation.Epoch-dtlsflight13.EpochApplication ||
			len(generation.Secret) != secretSize || generation.SequenceNumber > maxSequence {
			return dtlserrors.ErrInvalidProtectionInput
		}
		seen[generation.Epoch] = true
	}

	return nil
}

func (s *State) generateInternalState13(suite cryptosuite.Suite) (*dtlsstate.State13, error) {
	if err := s.validate13(suite); err != nil {
		return nil, err
	}
	factory, ok := suite.(cryptosuite.TrafficSuite)
	if !ok {
		return nil, dtlserrors.ErrInvalidCipherSuite
	}
	snapshot := s.state13
	state := &dtlsstate.State13{
		Common: s.restoreCommonState(suite, protocol.Version1_3),
		KeySchedule: dtlsstate.KeySchedule{
			ExporterMasterSecret:   bytes.Clone(s.exporterMasterSecret),
			ResumptionMasterSecret: bytes.Clone(snapshot.ResumptionMasterSecret),
		},
		TrafficKeys:           &dtlsstate.TrafficKeyState{},
		ReplayCutoff:          make(map[uint64]uint64),
		HandshakeSendSequence: snapshot.HandshakeSendSequence,
		HandshakeRecvSequence: snapshot.HandshakeRecvSequence,
		CID: dtlsstate.CIDState{
			Negotiated: snapshot.CIDNegotiated,
			Receive: dtlsstate.CIDReceiveState{
				IDs: &dtlsstate.CIDReceiveSet{}, Expected: len(s.localConnectionID) > 0,
				Length: len(s.localConnectionID), CanSendNewConnectionID: len(s.localConnectionID) > 0,
			},
			Send: snapshot.Send.Clone(),
		},
	}
	state.LocalCIDOffered, state.RemoteCIDOffered = snapshot.CIDNegotiated, snapshot.CIDNegotiated
	for _, id := range snapshot.ReceiveIDs {
		state.CID.Receive.IDs.Add(id)
	}
	if err := restoreTrafficGenerations(state, factory, snapshot.Write, true); err != nil {
		return nil, err
	}
	if err := restoreTrafficGenerations(state, factory, snapshot.Read, false); err != nil {
		return nil, err
	}
	state.SetLocalEpoch(snapshot.Write[len(snapshot.Write)-1].Epoch)
	state.SetRemoteEpoch(snapshot.Read[len(snapshot.Read)-1].Epoch)

	return state, nil
}

func restoreTrafficGenerations(state *dtlsstate.State13, suite cryptosuite.TrafficSuite, snapshots []serializedTrafficGeneration, write bool) error {
	for _, snapshot := range snapshots {
		secret := bytes.Clone(snapshot.Secret)
		trafficSecret, err := ciphersuite.NewTrafficSecret(secret)
		if err != nil {
			return err
		}
		protection, err := suite.NewTrafficProtection(trafficSecret)
		if err != nil {
			return err
		}
		generation := &dtlsstate.TrafficGeneration{
			Epoch: snapshot.Epoch, Generation: snapshot.Generation, Secret: secret, Protection: protection,
		}
		generation.RestoreUsage(snapshot.SealedRecords, snapshot.FailedRecords)
		if write {
			state.TrafficKeys.Install(generation, nil)
			state.SetLocalSequenceNumber(snapshot.Epoch, snapshot.SequenceNumber)
		} else {
			state.TrafficKeys.Install(nil, generation)
			if snapshot.SequenceNumberSeen {
				state.UpdateRemoteSequenceNumber(snapshot.Epoch, snapshot.SequenceNumber)
				state.ReplayCutoff[snapshot.Epoch] = snapshot.SequenceNumber
			}
		}
	}

	return nil
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
	s.deserialize(serialized)
	if s.CipherSuiteID == 0 {
		return dtlserrors.ErrCipherSuiteNotSet
	}
	if s.version == protocol.Version1_3 {
		if suite := ciphersuite.ForID(s.CipherSuiteID); suite != nil {
			return s.validate13(suite)
		}
		if s.state13 == nil {
			return dtlserrors.ErrInvalidProtectionInput
		}

		return nil
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
// slice as defined in https://www.rfc-editor.org/rfc/rfc5705.html#section-4
// for DTLS 1.2 and https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5
// for DTLS 1.3.
// This allows protocols to use DTLS for key establishment, but
// then use some of the keying material for their own purposes.
func (s *State) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	if s.localEpoch == 0 {
		return nil, dtlserrors.ErrHandshakeInProgress
	}

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

// exportKeyingMaterialPRF implements the DTLS 1.2 exporter from
// https://www.rfc-editor.org/rfc/rfc5705.html#section-4.
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

// exportKeyingMaterialHKDF implements the exporter from
// https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5 with the DTLS 1.3
// label prefix from https://www.rfc-editor.org/rfc/rfc9147.html#section-5.9.
func (s *State) exportKeyingMaterialHKDF(label string, context []byte, length int) ([]byte, error) {
	if len(s.exporterMasterSecret) == 0 {
		return nil, dtlserrors.ErrHandshakeInProgress
	}
	cipherSuite, err := s.cipherSuite()
	if err != nil {
		return nil, err
	}
	hashFunc := cipherSuite.HashFunc()

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
