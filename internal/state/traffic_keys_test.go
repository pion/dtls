// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"bytes"
	"math"
	"testing"

	"github.com/pion/dtls/v4/internal/ciphersuite"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
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
	assert.Equal(t, uint64(3), currentWrite.Epoch)
	assert.Equal(t, uint64(1), currentWrite.Generation)
	assert.Equal(t, writeSecret1, currentWrite.Secret)

	currentRead, ok := keys.CurrentRead()
	require.True(t, ok)
	assert.Equal(t, uint64(2), currentRead.Epoch)
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
	assert.Equal(t, uint64(3), currentRead.Epoch)
	assert.Equal(t, uint64(1), currentRead.Generation)
	assert.Equal(t, readSecret1, currentRead.Secret)
	oldRead, ok := keys.Read(2)
	require.True(t, ok)
	assert.Equal(t, readSecret0, oldRead.Secret)
}

func TestTrafficKeyStateReadCandidate(t *testing.T) {
	var keys TrafficKeyState
	for _, epoch := range []uint64{2, 3, 4, 5, 6, 7, 65538, math.MaxUint64} {
		keys.Install(nil, &TrafficGeneration{Epoch: epoch})
	}

	for _, test := range []struct {
		name    string
		current uint64
		low     uint8
		want    uint64
		found   bool
	}{
		{name: "current", current: 6, low: 2, want: 6, found: true},
		{name: "past", current: 6, low: 1, want: 5, found: true},
		{name: "unauthorized future", current: 6, low: 3, want: 3, found: true},
		{name: "missing current does not fall back", current: 10, low: 2},
		{name: "missing past does not fall back", current: 10, low: 1},
		{name: "invalid low bits", current: 6, low: 7},
		{name: "no past epoch", current: 1, low: 2},
		{name: "full width epoch", current: 65538, low: 2, want: 65538, found: true},
		{name: "maximum epoch", current: math.MaxUint64, low: 3, want: math.MaxUint64, found: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			generation, found := keys.ReadCandidate(test.low, test.current)
			require.Equal(t, test.found, found)
			if found {
				require.NotNil(t, generation)
				assert.Equal(t, test.want, generation.Epoch)
			} else {
				assert.Nil(t, generation)
			}
		})
	}
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
