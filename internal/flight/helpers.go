// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"slices"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	"github.com/pion/dtls/v3/internal/extensionnegotiation"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

func FindMatchingSRTPProfile(a, b []dtlsconfig.SRTPProtectionProfile) (dtlsconfig.SRTPProtectionProfile, bool) {
	for _, p1 := range a {
		if slices.Contains(b, p1) {
			return p1, true
		}
	}

	return 0, false
}

// CommitSRTP publishes a validated SRTP decision.
func CommitSRTP(state *dtlsstate.Common, decision extensionnegotiation.SRTPDecision) {
	if decision.ProtectionProfile != 0 {
		state.RemoteSRTPMasterKeyIdentifier = bytes.Clone(decision.PeerMasterKeyIdentifier)
	}
	state.SetSRTPProtectionProfile(decision.ProtectionProfile)
}

// SignatureSchemeIDs converts negotiated signature algorithms to their
// identifiers for the payload-oriented extension codecs.
func SignatureSchemeIDs(algorithms []signaturehash.Algorithm) []uint16 {
	ids := make([]uint16, 0, len(algorithms))
	for i := range algorithms {
		ids = append(ids, binary.BigEndian.Uint16(algorithms[i].Marshal()))
	}

	return ids
}

// SignatureSchemes converts known identifiers into algorithms used by
// negotiation. Unknown identifiers remain preserved by the extension value
// and are ignored here.
func SignatureSchemes(ids []uint16) []signaturehash.Algorithm {
	algorithms := make([]signaturehash.Algorithm, 0, len(ids))
	for _, id := range ids {
		var algorithm signaturehash.Algorithm
		if err := algorithm.Unmarshal(tls.SignatureScheme(id)); err == nil {
			algorithms = append(algorithms, algorithm)
		}
	}

	return algorithms
}

func FindMatchingCipherSuite(a, b []dtlsconfig.CipherSuite) (dtlsconfig.CipherSuite, bool) {
	for _, p1 := range a {
		for _, p2 := range b {
			if p1.ID() == p2.ID() {
				return p1, true
			}
		}
	}

	return nil, false
}

func CipherSuiteIDs(cipherSuites []dtlsconfig.CipherSuite) []uint16 {
	ids := []uint16{}
	for _, c := range cipherSuites {
		ids = append(ids, uint16(c.ID()))
	}

	return ids
}
