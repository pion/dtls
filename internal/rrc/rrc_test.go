// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rrc

import (
	"net"
	"testing"
	"time"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathValidation(t *testing.T) {
	manager := &Manager{}
	active := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}
	candidate := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 6000}
	other := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 7000}
	manager.recordReceived(candidate, active, 100)

	cookie, ok, err := manager.Start(true, candidate, active)
	require.NoError(t, err)
	require.True(t, ok)
	pendingCookie, ok, err := manager.Start(true, candidate, active)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Zero(t, pendingCookie)

	wrongCookie := cookie
	wrongCookie[0] ^= 0xff
	assert.False(t, manager.HandleResponse(candidate, wrongCookie))
	assert.False(t, manager.HandleResponse(other, cookie))
	assert.True(t, manager.HandleResponse(candidate, cookie))
}

func TestExpiredResponse(t *testing.T) {
	candidate := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 6000}
	cookie := [protocol.ReturnRoutabilityCheckCookieLength]byte{1, 2, 3}
	manager := &Manager{paths: map[string]*path{
		pathKey(candidate): {
			cookie:           cookie,
			challengePending: true,
			expiresAt:        time.Now().Add(-time.Second),
		},
	}}

	assert.False(t, manager.HandleResponse(candidate, cookie))
}

func TestAntiAmplificationBudgetIsPerCandidate(t *testing.T) {
	manager := &Manager{}
	active := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}
	first := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 6000}
	second := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 7000}
	manager.recordReceived(first, active, 10)
	manager.recordReceived(second, active, 4)

	require.NoError(t, manager.Reserve(first, active, 30))
	assert.ErrorIs(t, manager.Reserve(first, active, 1), dtlserrors.ErrAntiAmplificationLimit)
	require.NoError(t, manager.Reserve(second, active, 12))
	assert.ErrorIs(t, manager.Reserve(second, active, 1), dtlserrors.ErrAntiAmplificationLimit)
}

func TestReplayMarkerAccountsForRecordOnce(t *testing.T) {
	for name, latest := range map[string]bool{
		"Latest":    true,
		"NonLatest": false,
	} {
		t.Run(name, func(t *testing.T) {
			manager := &Manager{}
			active := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}
			candidate := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 6000}
			markerCalls := 0
			marker := manager.WrapReplayMarker(func() bool {
				markerCalls++

				return latest
			}, candidate, 10, func() net.Addr { return active }, true)

			assert.Equal(t, latest, marker())
			assert.Equal(t, latest, marker())
			assert.Equal(t, 2, markerCalls)
			manager.mu.Lock()
			defer manager.mu.Unlock()
			key := pathKey(candidate)
			require.Contains(t, manager.paths, key)
			assert.Equal(t, uint64(10), manager.paths[key].receivedBytes)
		})
	}
}
