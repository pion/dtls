// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"bytes"
	"slices"

	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/protocol"
)

// Clone13ForVerification returns a DTLS 1.3 state snapshot containing the
// certificates from the flight being verified.
func Clone13ForVerification(state *State13, peerCertificates [][]byte) *State13 {
	common := &Common{
		PeerCertificates: util.CloneByteSlices(peerCertificates),
		LocalVersion:     protocol.Version1_3,
	}
	if state == nil || state.Common == nil {
		return &State13{Common: common}
	}

	common.LocalSequenceNumber = slices.Clone(state.LocalSequenceNumber)
	common.RemoteSequenceNumber = slices.Clone(state.RemoteSequenceNumber)
	common.LocalRandom = state.LocalRandom
	common.RemoteRandom = state.RemoteRandom
	common.CipherSuite = state.CipherSuite
	common.IdentityHint = bytes.Clone(state.IdentityHint)
	common.SessionID = bytes.Clone(state.SessionID)
	common.NegotiatedProtocol = state.NegotiatedProtocol
	common.RemoteSRTPMasterKeyIdentifier = bytes.Clone(state.RemoteSRTPMasterKeyIdentifier)
	common.RemoteConnectionID = bytes.Clone(state.RemoteConnectionID)
	common.IsClient = state.IsClient
	common.ServerName = state.ServerName
	common.PeerSupportedProtocols = slices.Clone(state.PeerSupportedProtocols)
	common.RemoteVersions = slices.Clone(state.RemoteVersions)
	if !state.LocalVersion.Equal(protocol.Version{}) {
		common.LocalVersion = state.LocalVersion
	}
	common.SetLocalEpoch(state.LocalEpoch())
	common.SetRemoteEpoch(state.RemoteEpoch())
	common.SetSRTPProtectionProfile(state.SRTPProtectionProfile())
	if localCID := state.LocalConnectionID(); localCID != nil {
		common.SetLocalConnectionID(bytes.Clone(localCID))
	}

	cid := state.CID
	cid.Send.Active = bytes.Clone(state.CID.Send.Active)

	return &State13{
		Common:                     common,
		CID:                        cid,
		KeySchedule:                cloneKeySchedule(state.KeySchedule),
		TrafficKeys:                state.TrafficKeys.Clone(),
		KeyAgreementSecret:         bytes.Clone(state.KeyAgreementSecret),
		SelectedGroup:              state.SelectedGroup,
		LocalKeyEntries:            slices.Clone(state.LocalKeyEntries),
		RemoteKeyEntries:           slices.Clone(state.RemoteKeyEntries),
		HasRemoteKeyEntries:        state.HasRemoteKeyEntries,
		RemoteGroups:               slices.Clone(state.RemoteGroups),
		Cookie:                     bytes.Clone(state.Cookie),
		HandshakeSendSequence:      state.HandshakeSendSequence,
		HandshakeRecvSequence:      state.HandshakeRecvSequence,
		RemoteSignatureSchemes:     slices.Clone(state.RemoteSignatureSchemes),
		RemoteCertSignatureSchemes: slices.Clone(state.RemoteCertSignatureSchemes),
	}
}

func cloneKeySchedule(in KeySchedule) KeySchedule {
	return KeySchedule{
		EarlySecret:                     bytes.Clone(in.EarlySecret),
		HandshakeSecret:                 bytes.Clone(in.HandshakeSecret),
		MasterSecret:                    bytes.Clone(in.MasterSecret),
		HandshakeTraffic:                cloneTrafficSecrets(in.HandshakeTraffic),
		ClientApplicationTrafficSecret0: bytes.Clone(in.ClientApplicationTrafficSecret0),
		ServerApplicationTrafficSecret0: bytes.Clone(in.ServerApplicationTrafficSecret0),
		ExporterMasterSecret:            bytes.Clone(in.ExporterMasterSecret),
		ResumptionMasterSecret:          bytes.Clone(in.ResumptionMasterSecret),
	}
}

func cloneTrafficSecrets(in TrafficSecrets) TrafficSecrets {
	return TrafficSecrets{
		Client: bytes.Clone(in.Client),
		Server: bytes.Clone(in.Server),
	}
}
