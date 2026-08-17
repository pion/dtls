// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"bytes"
	"testing"

	"github.com/pion/dtls/v3/internal/extensionnegotiation"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertConnectionIDs(t *testing.T, state *Common, local, remote []byte, negotiated bool) {
	t.Helper()
	assert.Equal(t, local, state.LocalConnectionID())
	assert.Equal(t, remote, state.RemoteConnectionID)
	assert.Equal(t, [2]bool{negotiated, negotiated}, [2]bool{state.LocalCIDOffered, state.RemoteCIDOffered})
}

func assertConnectionIDs13(t *testing.T, state *State13, local, remote []byte, negotiated bool) {
	t.Helper()
	assertConnectionIDs(t, state.Common, local, remote, negotiated)
	if !negotiated {
		assert.Zero(t, state.CID)

		return
	}
	hasLocal := len(local) > 0
	assert.Equal(t, [3]bool{true, hasLocal, hasLocal},
		[3]bool{state.CID.Negotiated, state.CID.Receive.Expected, state.CID.Receive.CanSendNewConnectionID})
	assert.Equal(t, len(local), state.CID.Receive.Length)
	assert.Equal(t, len(remote) > 0, state.CID.Send.UseCID)
	assert.Equal(t, remote, state.CID.Send.Active)
}

func TestCommitNegotiatedExtensions(t *testing.T) {
	clientCID := []byte{0x01, 0x02}
	serverCID := []byte{0x10, 0x11, 0x12}
	empty := []byte{}
	tests := []struct {
		name           string
		isClient       bool
		client, server []byte
		negotiated     bool
	}{
		{"client", true, clientCID, serverCID, true},
		{"server", false, clientCID, serverCID, true},
		{"client empty CID", true, nil, empty, true},
		{"server empty CID", false, nil, empty, true},
		{"both nil", true, nil, nil, true},
		{"declined", true, nil, nil, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			local, remote := test.server, test.client
			if test.isClient {
				local, remote = remote, local
			}
			var decision *extensionnegotiation.ConnectionID
			if test.negotiated {
				decision = &extensionnegotiation.ConnectionID{
					ClientCID: bytes.Clone(test.client), ServerCID: bytes.Clone(test.server),
				}
			}
			state12, state13 := NewState12(test.isClient), NewState13(test.isClient)
			state12.SetLocalConnectionID([]byte{0xff})
			state12.LocalCIDOffered, state12.RemoteCIDOffered = true, true
			state12.RemoteConnectionID = []byte{0xff}
			state13.CommitNegotiatedExtensions(&extensionnegotiation.ConnectionID{ClientCID: []byte{0xff}, ServerCID: []byte{0xff}}) //nolint:lll

			state12.CommitNegotiatedExtensions(decision)
			state13.CommitNegotiatedExtensions(decision)
			assertConnectionIDs(t, state12.Common, local, remote, test.negotiated)
			assertConnectionIDs13(t, &state13, local, remote, test.negotiated)

			if decision != nil {
				clone := Clone13ForVerification(&state13, nil)
				if len(decision.ClientCID) > 0 {
					decision.ClientCID[0] = 0xff
				}
				if len(decision.ServerCID) > 0 {
					decision.ServerCID[0] = 0xff
				}
				assertConnectionIDs(t, state12.Common, local, remote, true)
				assertConnectionIDs13(t, &state13, local, remote, true)
				if len(local) > 0 {
					state13.LocalConnectionID()[0] = 0xee
				}
				if len(remote) > 0 {
					state13.RemoteConnectionID[0] = 0xee
					assert.Equal(t, remote, state13.CID.Send.Active)
					state13.CID.Send.Active[0] = 0xee
				}
				assertConnectionIDs13(t, clone, local, remote, true)
			}
		})
	}
}

func TestRecordLocalClientHelloTracksCIDPresence(t *testing.T) {
	for _, extensions := range [][]extension.Value{nil, {&extension.ConnectionID{}}} {
		_, snapshot, err := extensionnegotiation.FinalizeClientHello(
			&handshake.MessageClientHello{Extensions: extensions}, nil,
		)
		require.NoError(t, err)
		state := NewState12(true)
		require.NoError(t, state.RecordLocalClientHello(snapshot))
		assert.Equal(t, len(extensions) > 0, state.pendingLocalConnectionID.Load() != nil)
	}
}
