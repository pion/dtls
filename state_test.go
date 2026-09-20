// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"encoding/gob"
	"testing"
	"time"

	"github.com/pion/dtls/v4/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func TestGenerateStateRejectsDTLS13(t *testing.T) {
	internalState := &dtlsstate.State{Common: &dtlsstate.Common{LocalVersion: protocol.Version1_3, CipherSuite: ciphersuite.ForID(cryptosuite.TLS_AES_128_GCM_SHA256)}}

	_, err := generateState(internalState)
	require.ErrorIs(t, err, ErrStateSerializationUnsupported)
}

func TestUnmarshalBinaryRejectsDTLS13State(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, gob.NewEncoder(&buf).Encode(serializedState{Version: protocol.Version1_3, CipherSuiteID: uint16(cryptosuite.TLS_AES_128_GCM_SHA256)}))

	var state State
	err := state.UnmarshalBinary(buf.Bytes())
	require.ErrorIs(t, err, ErrStateSerializationUnsupported)
}

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

// TestConnectionStateRoleAndVersion negotiates a real connection and checks that
// both peers report the role they actually took and the version they agreed on.
func TestConnectionStateRoleAndVersion(t *testing.T) {
	for _, test := range []struct {
		name    string
		version protocol.Version
	}{
		{"DTLS1.2", protocol.Version1_2},
		{"DTLS1.3", protocol.Version1_3},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := packetPipe()
			type result struct {
				c   *Conn
				err error
			}
			resultCh := make(chan result, 1)

			go func() {
				client, err := testClient(ctx, ca, ca.RemoteAddr(), []ClientOption{WithMinVersion(test.version), WithMaxVersion(test.version)}, true)
				resultCh <- result{client, err}
			}()

			server, err := testServer(ctx, cb, cb.RemoteAddr(), []ServerOption{WithMinVersion(test.version), WithMaxVersion(test.version)}, true)
			require.NoError(t, err)

			res := <-resultCh
			require.NoError(t, res.err)

			defer func() {
				require.NoError(t, res.c.Close())
				require.NoError(t, server.Close())
			}()

			clientState, ok := res.c.ConnectionState()
			require.True(t, ok)
			serverState, ok := server.ConnectionState()
			require.True(t, ok)

			require.Equal(t, RoleClient, clientState.Role())
			require.Equal(t, RoleServer, serverState.Role())
			require.True(t, clientState.NegotiatedVersion() == test.version)
			require.True(t, serverState.NegotiatedVersion() == test.version)
			require.NotNil(t, clientState.KeyUsage)
			require.NotNil(t, serverState.KeyUsage)
			require.Equal(t, uint64(23726566), clientState.KeyUsage.RecommendedLimits.MaxSealedRecords)
			if test.version == protocol.Version1_2 {
				require.Equal(t, uint64(1<<28), clientState.KeyUsage.RecommendedLimits.MaxAuthenticationFailures)
			}
		})
	}
}
