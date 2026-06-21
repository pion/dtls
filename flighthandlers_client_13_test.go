// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlight13_1ParseStoresHelloRetryRequestSelectedGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384
	cipherSuiteID := uint16(cfg.localCipherSuites[0].ID())

	var hrrRandomFixed [handshake.RandomLength]byte
	copy(hrrRandomFixed[:], handshake.HelloRetryRequestRandom())
	var hrrRandom handshake.Random
	hrrRandom.UnmarshalFixed(hrrRandomFixed)

	serverHello := &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		Random:            hrrRandom,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: defaultCompressionMethods()[0],
		Extensions: []extension.Extension{
			&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}},
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	}
	rawServerHello, err := (&handshake.Handshake{Message: serverHello}).Marshal()
	require.NoError(t, err)

	state := &State{}
	cache := newHandshakeCache()
	cache.push(rawServerHello, cfg.initialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13_1Parse(context.Background(), nil, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, flight13_3, nextFlight)
	require.Len(t, state.remoteKeyEntries, 1)

	entries := *state.remoteKeyEntries
	assert.Equal(t, selectedGroup, entries[0].Group)
	assert.Empty(t, entries[0].KeyExchange)
}
