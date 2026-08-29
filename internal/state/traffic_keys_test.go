// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"bytes"
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrafficKeyStateAdvancesDirectionsIndependently(t *testing.T) {
	suite := ciphersuite.ForID(cryptosuite.TLS_AES_128_GCM_SHA256)
	factory := suite.(cryptosuite.TrafficSuite) //nolint:forcetypeassert // fixed built-in registry.
	secretSize := suite.HashFunc()().Size()
	writeSecret0 := bytes.Repeat([]byte{0x10}, secretSize)
	readSecret0 := bytes.Repeat([]byte{0x20}, secretSize)
	writeSecret1 := bytes.Repeat([]byte{0x11}, secretSize)
	readSecret1 := bytes.Repeat([]byte{0x21}, secretSize)

	writeTrafficSecret0, err := ciphersuite.NewTrafficSecret(writeSecret0)
	require.NoError(t, err)
	writeProtection0, err := factory.NewTrafficProtection(writeTrafficSecret0)
	require.NoError(t, err)
	readTrafficSecret0, err := ciphersuite.NewTrafficSecret(readSecret0)
	require.NoError(t, err)
	readProtection0, err := factory.NewTrafficProtection(readTrafficSecret0)
	require.NoError(t, err)
	writeTrafficSecret1, err := ciphersuite.NewTrafficSecret(writeSecret1)
	require.NoError(t, err)
	writeProtection1, err := factory.NewTrafficProtection(writeTrafficSecret1)
	require.NoError(t, err)
	readTrafficSecret1, err := ciphersuite.NewTrafficSecret(readSecret1)
	require.NoError(t, err)
	readProtection1, err := factory.NewTrafficProtection(readTrafficSecret1)
	require.NoError(t, err)

	var keys TrafficKeyState
	keys.Install(&TrafficGeneration{Epoch: 2, Generation: 0, Secret: writeSecret0, Protection: writeProtection0}, &TrafficGeneration{Epoch: 2, Generation: 0, Secret: readSecret0, Protection: readProtection0})
	keys.Install(&TrafficGeneration{
		Epoch:      3,
		Generation: 1,
		Secret:     writeSecret1,
		Protection: writeProtection1,
	}, nil)

	currentWrite, ok := keys.CurrentWrite()
	require.True(t, ok)
	assert.Equal(t, uint16(3), currentWrite.Epoch)
	assert.Equal(t, uint64(1), currentWrite.Generation)
	assert.Equal(t, writeSecret1, currentWrite.Secret)

	currentRead, ok := keys.CurrentRead()
	require.True(t, ok)
	assert.Equal(t, uint16(2), currentRead.Epoch)
	assert.Equal(t, readSecret0, currentRead.Secret)
	_, ok = keys.Read(3)
	assert.False(t, ok)

	oldWrite, ok := keys.Write(2)
	require.True(t, ok)
	assert.Equal(t, writeSecret0, oldWrite.Secret)

	keys.Install(nil, &TrafficGeneration{
		Epoch:      3,
		Generation: 1,
		Secret:     readSecret1,
		Protection: readProtection1,
	})
	currentRead, ok = keys.CurrentRead()
	require.True(t, ok)
	assert.Equal(t, uint16(3), currentRead.Epoch)
	assert.Equal(t, uint64(1), currentRead.Generation)
	assert.Equal(t, readSecret1, currentRead.Secret)
	oldRead, ok := keys.Read(2)
	require.True(t, ok)
	assert.Equal(t, readSecret0, oldRead.Secret)
}

func TestTrafficKeyStateReadCandidates(t *testing.T) {
	var keys TrafficKeyState
	readGenerations := []*TrafficGeneration{
		{Epoch: 2},
		{Epoch: 3},
		{Epoch: 4},
		{Epoch: 5},
		{Epoch: 6},
	}
	for _, generation := range readGenerations {
		keys.Install(nil, generation)
	}

	storage := make([]*TrafficGeneration, 0, 2)
	candidates := keys.ReadCandidates(2, storage)
	require.Len(t, candidates, 2)
	assert.Same(t, readGenerations[4], candidates[0], "current generation must be tried first")
	assert.Same(t, readGenerations[0], candidates[1])

	candidates = keys.ReadCandidates(0, storage[:0])
	require.Len(t, candidates, 1)
	assert.Same(t, readGenerations[2], candidates[0])

	candidates = keys.ReadCandidates(1, storage[:0])
	require.Len(t, candidates, 1)
	assert.Same(t, readGenerations[3], candidates[0])

	assert.Empty(t, keys.ReadCandidates(7, storage[:0]))
}

func TestTrafficGenerationCloneCopiesSecret(t *testing.T) {
	suite := ciphersuite.ForID(cryptosuite.TLS_AES_128_GCM_SHA256)
	factory := suite.(cryptosuite.TrafficSuite) //nolint:forcetypeassert // fixed built-in registry.
	secret := bytes.Repeat([]byte{0x42}, suite.HashFunc()().Size())
	trafficSecret, err := ciphersuite.NewTrafficSecret(secret)
	require.NoError(t, err)
	protection, err := factory.NewTrafficProtection(trafficSecret)
	require.NoError(t, err)

	generation := &TrafficGeneration{
		Epoch:      7,
		Generation: 3,
		Secret:     secret,
		Protection: protection,
	}
	clone := generation.Clone()
	secret[0] ^= 0xff
	assert.Equal(t, byte(0x42), clone.Secret[0])
	clone.Secret[0] ^= 0xff
	assert.Equal(t, byte(0xbd), generation.Secret[0])
	assert.NotNil(t, clone.Protection)
}
