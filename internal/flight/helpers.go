// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"slices"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	"github.com/pion/dtls/v3/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
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
func CommitSRTP(state *dtlsstate.Common, decision negotiation.SRTPDecision) {
	if decision.ProtectionProfile != 0 {
		state.RemoteSRTPMasterKeyIdentifier = bytes.Clone(decision.PeerMasterKeyIdentifier)
	}
	state.SetSRTPProtectionProfile(decision.ProtectionProfile)
}

// AppendConnectionIDExtensions appends a connection ID and, when enabled, RRC.
func AppendConnectionIDExtensions(
	values []extension.Value,
	cid []byte,
	enableRRC bool,
) []extension.Value {
	values = append(values, &extension.ConnectionID{CID: bytes.Clone(cid)})
	if enableRRC {
		values = append(values, &extension.ReturnRoutabilityCheck{})
	}

	return values
}

// FinalizeClientHello applies the hook and prevents it from enabling RRC when
// the configured CID path-migration policy does not permit RRC.
func FinalizeClientHello(
	base *handshake.MessageClientHello,
	hook func(handshake.MessageClientHello) handshake.Message,
	enableRRC bool,
) (*handshake.MessageClientHello, negotiation.ClientHelloSnapshot, error) {
	clientHello, snapshot, err := negotiation.FinalizeClientHello(base, hook)
	if err != nil || enableRRC || !snapshot.Offered(extension.TypeReturnRoutabilityCheck) {
		return clientHello, snapshot, err
	}

	clientHello.Extensions = withoutExtension(clientHello.Extensions, extension.TypeReturnRoutabilityCheck)

	return negotiation.FinalizeClientHello(clientHello, nil)
}

// FinalizeServerHello applies the hook and prevents it from enabling RRC when
// the configured CID path-migration policy does not permit RRC.
func FinalizeServerHello(
	base *handshake.MessageServerHello,
	hook func(handshake.MessageServerHello) handshake.Message,
	offer negotiation.ClientHelloSnapshot,
	enableRRC bool,
) (*handshake.MessageServerHello, error) {
	serverHello, err := negotiation.FinalizeServerHello(base, hook, offer)
	if err != nil || enableRRC {
		return serverHello, err
	}

	serverHello.Extensions = withoutExtension(serverHello.Extensions, extension.TypeReturnRoutabilityCheck)

	return serverHello, nil
}

func withoutExtension(values []extension.Value, typ extension.Type) []extension.Value {
	filtered := make([]extension.Value, 0, len(values))
	for _, value := range values {
		if value.ExtensionType() != typ {
			filtered = append(filtered, value)
		}
	}

	return filtered
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
