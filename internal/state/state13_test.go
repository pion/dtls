// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestState13NegotiateConnectionIDsPreservesNilValues(t *testing.T) {
	state := NewState13(true)
	state.SetLocalConnectionID(nil)
	state.LocalCIDOffered = true

	state.NegotiateConnectionIDs(nil)

	assert.True(t, state.LocalCIDOffered)
	assert.True(t, state.RemoteCIDOffered)
	assert.Nil(t, state.LocalConnectionID())
	assert.Nil(t, state.RemoteConnectionID)
	assert.True(t, state.CID.Negotiated)
	assert.False(t, state.CID.Receive.Expected)
	assert.Zero(t, state.CID.Receive.Length)
	assert.False(t, state.CID.Send.UseCID)
	assert.Nil(t, state.CID.Send.Active)
}

func TestState13NegotiateConnectionIDsClonesValues(t *testing.T) {
	localCID := []byte{0x01, 0x02}
	remoteCID := []byte{0x10, 0x11}
	state := NewState13(true)
	state.SetLocalConnectionID(localCID)
	state.LocalCIDOffered = true

	state.NegotiateConnectionIDs(remoteCID)
	localCID[0] = 0xff
	remoteCID[0] = 0xff

	assert.Equal(t, []byte{0x01, 0x02}, state.LocalConnectionID())
	assert.Equal(t, []byte{0x10, 0x11}, state.RemoteConnectionID)
	assert.Equal(t, []byte{0x10, 0x11}, state.CID.Send.Active)

	state.RemoteConnectionID[0] = 0xee
	assert.Equal(t, []byte{0x10, 0x11}, state.CID.Send.Active)
}
