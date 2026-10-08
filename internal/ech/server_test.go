// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ech

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAcceptanceConfirmation(t *testing.T) {
	for _, hashFunc := range []func() hash.Hash{sha256.New, sha512.New384} {
		inner := bytes.Repeat([]byte{3}, 50)
		server := bytes.Repeat([]byte{4}, 45)
		before := bytes.Clone(server)
		actual, err := AcceptanceConfirmation(hashFunc, inner, server)
		require.NoError(t, err)
		require.Equal(t, before, server)
		extract := hmac.New(hashFunc, make([]byte, hashFunc().Size()))
		_, err = extract.Write(inner[2:34])
		require.NoError(t, err)
		digest := hashFunc()
		_, err = digest.Write([]byte{1, 0, 0, 50})
		require.NoError(t, err)
		_, err = digest.Write(inner)
		require.NoError(t, err)
		_, err = digest.Write([]byte{2, 0, 0, 45})
		require.NoError(t, err)
		clear(server[26:34])
		_, err = digest.Write(server)
		require.NoError(t, err)
		label := []byte("dtls13ech accept confirmation")
		info := append([]byte{0, 8, 29}, label...)
		info = append(info, byte(len(digest.Sum(nil))&0xff))
		info = append(info, digest.Sum(nil)...)
		expand := hmac.New(hashFunc, extract.Sum(nil))
		_, err = expand.Write(append(info, 1))
		require.NoError(t, err)
		require.Equal(t, expand.Sum(nil)[:8], actual)
		inner[2] ^= 1
		changed, err := AcceptanceConfirmation(hashFunc, inner, server)
		require.NoError(t, err)
		require.NotEqual(t, actual, changed)
	}
}
