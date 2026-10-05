// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"testing"
	"time"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
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

func TestResume(t *testing.T) {
	for _, test := range []struct {
		name    string
		version protocol.Version
		suite   cryptosuite.ID
	}{
		{"DTLS12", protocol.Version1_2, cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		{"DTLS13/AES128", protocol.Version1_3, cryptosuite.TLS_AES_128_GCM_SHA256},
		{"DTLS13/AES256", protocol.Version1_3, cryptosuite.TLS_AES_256_GCM_SHA384},
		{"DTLS13/ChaCha20", protocol.Version1_3, cryptosuite.TLS_CHACHA20_POLY1305_SHA256},
	} {
		for mode, binary := range map[string]bool{"State": false, "Binary": true} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				cert, err := selfsign.GenerateSelfSigned()
				require.NoError(t, err)
				client, server := handshakePair(t, []ClientOption{
					WithInsecureSkipVerify(true), WithCipherSuites(test.suite),
					WithMinVersion(test.version), WithMaxVersion(test.version),
					WithConnectionID(func() []byte { return []byte("client") }, CIDPathMigrationReject),
					WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80),
					WithSRTPMasterKeyIdentifier([]byte{1}),
				}, []ServerOption{
					WithCertificates(cert), WithCipherSuites(test.suite),
					WithMinVersion(test.version), WithMaxVersion(test.version),
					WithConnectionID(func() []byte { return []byte("server") }, CIDPathMigrationReject),
					WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80),
					WithSRTPMasterKeyIdentifier([]byte{2}),
				})
				require.NoError(t, client.configErr)
				require.NoError(t, server.configErr)
				require.NoError(t, client.handshakeError)
				require.NoError(t, server.handshakeError)
				exchangeResumeData(t, client.conn, server.conn)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if test.version == protocol.Version1_3 {
					// Exercise independent read/write epochs and retain an older key.
					require.NoError(t, client.conn.UpdateKeys(ctx, KeyUpdateOptions{}))
					exchangeResumeData(t, client.conn, server.conn)
				}
				clientState, ok := client.conn.ConnectionState()
				require.True(t, ok)
				serverState, ok := server.conn.ConnectionState()
				require.True(t, ok)
				exported, err := clientState.ExportKeyingMaterial("resume-test", nil, 32)
				require.NoError(t, err)
				// Stop the old transport without sending a close_notify record.
				require.NoError(t, client.conn.close(false))
				require.NoError(t, server.conn.close(false))
				if binary {
					for _, state := range []*State{&clientState, &serverState} {
						data, marshalErr := state.MarshalBinary()
						require.NoError(t, marshalErr)
						*state = State{}
						require.NoError(t, state.UnmarshalBinary(data))
					}
				}
				ca, cb := packetPipe()
				t.Cleanup(func() { _ = ca.Close(); _ = cb.Close() })
				resumedClient, err := Resume(&clientState, ca, ca.RemoteAddr())
				require.NoError(t, err)
				t.Cleanup(func() { _ = resumedClient.Close() })
				resumedServer, err := Resume(&serverState, cb, cb.RemoteAddr())
				require.NoError(t, err)
				t.Cleanup(func() { _ = resumedServer.Close() })
				// Each endpoint must restore without waiting for a new handshake.
				require.NoError(t, resumedClient.HandshakeContext(ctx))
				require.NoError(t, resumedServer.HandshakeContext(ctx))
				restored, ok := resumedClient.ConnectionState()
				require.True(t, ok)
				require.Equal(t, test.version, restored.NegotiatedVersion())
				actual, err := restored.ExportKeyingMaterial("resume-test", nil, 32)
				require.NoError(t, err)
				require.Equal(t, exported, actual)
				if test.version == protocol.Version1_3 {
					state, is13 := resumedServer.state.(*dtlsstate.State13)
					require.True(t, is13)
					for epoch, cutoff := range state.ReplayCutoff {
						_, accepted := resumedServer.replayMarker(epoch, cutoff, ^uint64(0))
						require.False(t, accepted, "previously received records must remain rejected")
					}
				}
				exchangeResumeData(t, resumedClient, resumedServer)
				if test.version == protocol.Version1_3 {
					require.NoError(t, resumedServer.UpdateKeys(ctx, KeyUpdateOptions{}))
					require.NoError(t, resumedClient.UpdateKeys(ctx, KeyUpdateOptions{}))
					exchangeResumeData(t, resumedClient, resumedServer)
				}
			})
		}
	}
}

func exchangeResumeData(t *testing.T, client, server *Conn) {
	t.Helper()
	for _, pair := range [][2]*Conn{{client, server}, {server, client}} {
		require.NoError(t, pair[0].SetWriteDeadline(time.Now().Add(5*time.Second)))
		require.NoError(t, pair[1].SetReadDeadline(time.Now().Add(5*time.Second)))
		written := make(chan error, 1)
		go func() { _, err := pair[0].Write([]byte("resumed data")); written <- err }()
		buffer := make([]byte, 100)
		n, err := pair[1].Read(buffer)
		require.NoError(t, err)
		require.Equal(t, "resumed data", string(buffer[:n]))
		require.NoError(t, <-written)
	}
}
