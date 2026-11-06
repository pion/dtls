// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package elliptic

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestString(t *testing.T) {
	tests := []struct {
		in  Curve
		out string
	}{
		{X25519, "X25519"},
		{P256, "P-256"},
		{P384, "P-384"},
		{X25519MLKEM768, "X25519MLKEM768"},
		{0, "0x0"},
	}

	for _, tt := range tests {
		t.Run(tt.out, func(t *testing.T) {
			assert.Equal(t, tt.in.String(), tt.out)
		})
	}
}

func TestGenerateKeypair_InvalidCurve(t *testing.T) {
	var invalid Curve = 0 // not a supported curve
	_, err := GenerateKeypair(invalid)
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidNamedCurve)
}

func TestGenerateKeypair_X25519MLKEM768ClientShare(t *testing.T) {
	assert.True(t, Curves()[X25519MLKEM768])

	keypair, err := GenerateKeypair(X25519MLKEM768)
	require.NoError(t, err)
	assert.Equal(t, X25519MLKEM768, keypair.Curve)
	assert.Len(t, keypair.PublicKey, X25519MLKEM768ClientPublicKeySize)
	assert.Len(t, keypair.PrivateKey, X25519MLKEM768ClientPrivateKeySize)
}

func TestGenerateKeypairForPeer_X25519MLKEM768ServerShare(t *testing.T) {
	clientKeypair, err := GenerateKeypair(X25519MLKEM768)
	require.NoError(t, err)

	serverKeypair, err := GenerateKeypairForPeer(X25519MLKEM768, clientKeypair.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, X25519MLKEM768, serverKeypair.Curve)
	assert.Len(t, serverKeypair.PublicKey, X25519MLKEM768ServerPublicKeySize)
	assert.Len(t, serverKeypair.PrivateKey, X25519MLKEM768ServerPrivateKeySize)
}

func TestGenerateKeypairForPeer_X25519MLKEM768RejectsBadPeerShareLength(t *testing.T) {
	_, err := GenerateKeypairForPeer(X25519MLKEM768, []byte{0x01})
	assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)
}

func TestToECDH_InvalidCurve(t *testing.T) {
	var invalid Curve = 0xFFFF
	_, err := invalid.toECDH()
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidNamedCurve)
}
