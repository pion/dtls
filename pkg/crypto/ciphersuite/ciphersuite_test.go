// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func TestCapabilitySizing(t *testing.T) {
	aead, err := NewAEADCapabilities(protocol.Version1_2, 64, 0, 16, 0)
	require.NoError(t, err)
	protectedLen, err := aead.ProtectedLen(37)
	require.NoError(t, err)
	require.Equal(t, 53, protectedLen)
	upper, err := aead.PlaintextLenUpperBound(protectedLen)
	require.NoError(t, err)
	require.Equal(t, 37, upper)
	require.NoError(t, aead.ValidatePlaintextLen(protectedLen, 37))
	require.ErrorIs(t, aead.ValidatePlaintextLen(protectedLen, 36), ErrInvalidCapabilities)

	cbc, err := NewCBCCapabilities(64, 32, 16)
	require.NoError(t, err)
	protectedLen, err = cbc.ProtectedLen(37)
	require.NoError(t, err)
	require.Equal(t, 96, protectedLen)
	upper, err = cbc.PlaintextLenUpperBound(protectedLen)
	require.NoError(t, err)
	require.Equal(t, 47, upper)
	require.NoError(t, cbc.ValidatePlaintextLen(protectedLen, 37))
	require.NoError(t, cbc.ValidatePlaintextLen(protectedLen+16, 37), "legal non-minimal CBC padding")
	require.ErrorIs(t, cbc.ValidatePlaintextLen(129, 37), ErrInvalidCapabilities)
}
