// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"slices"
	"testing"
	"time"

	dtlsstate "github.com/pion/dtls/v3/internal/state"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/transport/v4/dpipe"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Assert that supported_groups advertises every configured group in order.
func TestSupportedGroups(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	supportedGroups := elliptic.Curves()
	require.Contains(t, supportedGroups, elliptic.X25519MLKEM768)
	expectedGroups := make([]elliptic.Curve, 0, len(supportedGroups))
	for group := range supportedGroups {
		expectedGroups = append(expectedGroups, group)
	}
	expectedGroups = effectiveEllipticCurves(expectedGroups)
	slices.Sort(expectedGroups)
	slices.Reverse(expectedGroups)

	type result struct {
		conn *Conn
		err  error
	}
	clientResult := make(chan result, 1)
	ca, cb := dpipe.Pipe()

	go func() {
		client, err := testClient(
			ctx,
			dtlsnet.PacketConnFromConn(ca),
			ca.RemoteAddr(),
			[]ClientOption{
				WithCipherSuites(cryptosuite.TLS_AES_128_GCM_SHA256),
				WithEllipticCurves(expectedGroups...),
				WithMinVersion(protocol.Version1_3),
				WithMaxVersion(protocol.Version1_3),
			},
			false,
		)
		clientResult <- result{conn: client, err: err}
	}()

	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), []ServerOption{
		WithCipherSuites(cryptosuite.TLS_AES_128_GCM_SHA256),
		WithMinVersion(protocol.Version1_3),
		WithMaxVersion(protocol.Version1_3),
	}, true)
	client := <-clientResult
	defer func() {
		if server != nil {
			assert.NoError(t, server.Close())
		}
		if client.conn != nil {
			assert.NoError(t, client.conn.Close())
		}
	}()

	require.NoError(t, err)
	require.NoError(t, client.err)
	serverState, ok := server.state.(*dtlsstate.State13)
	require.True(t, ok)
	require.Equal(t, expectedGroups, serverState.RemoteGroups, "groups in supported_groups mismatch")
}
