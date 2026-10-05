// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/stretchr/testify/require"
)

func TestStateRejectsDTLS12EpochOverflow(t *testing.T) {
	for _, epoch := range []uint64{1 << 16, 1 << 32, ^uint64(0)} {
		for _, state := range []State{
			{localEpoch: epoch, CipherSuiteID: cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			{remoteEpoch: epoch, CipherSuiteID: cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		} {
			_, err := state.MarshalBinary()
			require.ErrorIs(t, err, dtlserrors.ErrEpochOverflow)
			_, err = state.generateInternalState()
			require.ErrorIs(t, err, dtlserrors.ErrEpochOverflow)
		}
	}
}

func TestStatePreservesPeerSRTPMKI(t *testing.T) {
	state := State{CipherSuiteID: cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, srtpProtectionProfile: SRTP_AES128_CM_HMAC_SHA1_80, peerSRTPMKI: []byte{1, 2}}
	serialized, err := state.serialize()
	require.NoError(t, err)

	var restored State
	restored.deserialize(*serialized)
	serialized.PeerSRTPMKI[0] = 0xff
	require.Equal(t, []byte{1, 2}, restored.peerSRTPMKI)
}

func TestStatePreservesReturnRoutabilityCheck(t *testing.T) {
	state := State{
		CipherSuiteID: cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		rrcNegotiated: true,
	}
	serialized, err := state.serialize()
	require.NoError(t, err)

	var restored State
	restored.deserialize(*serialized)
	require.True(t, restored.rrcNegotiated)
}
