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

func TestRetryConfirmations(t *testing.T) {
	for _, hashFunc := range []func() hash.Hash{sha256.New, sha512.New384} {
		first := bytes.Repeat([]byte{3}, 50)
		second := bytes.Clone(first)
		second = append(second, 4)
		hrr := bytes.Repeat([]byte{5}, 60)
		clear(hrr[52:]) // Zeroed ECH confirmation extension.
		final := bytes.Repeat([]byte{6}, 45)
		clear(final[26:34])
		canonical := func(typ byte, body []byte) []byte {
			return append([]byte{typ, 0, 0, byte(len(body) & 0xff)}, body...)
		}
		digest := hashFunc()
		_, _ = digest.Write(canonical(1, first))
		prefix := canonical(254, digest.Sum(nil))
		context := ServerContext{InitialInner: first, Inner: second, HelloRetryRequest: hrr}
		for _, retry := range []bool{true, false} {
			label := "dtls13ech accept confirmation"
			transcript := bytes.Clone(prefix)
			transcript = append(transcript, canonical(2, hrr)...)
			if !retry {
				transcript = append(transcript, canonical(1, second)...)
				transcript = append(transcript, canonical(2, final)...)
			} else {
				label = "dtls13hrr ech accept confirmation"
			}
			extract := hmac.New(hashFunc, make([]byte, hashFunc().Size()))
			_, _ = extract.Write(first[2:34])
			digest.Reset()
			_, _ = digest.Write(transcript)
			info := append([]byte{0, 8, byte(len(label) & 0xff)}, []byte(label)...)
			info = append(info, byte(digest.Size()&0xff))
			info = append(info, digest.Sum(nil)...)
			expand := hmac.New(hashFunc, extract.Sum(nil))
			_, _ = expand.Write(append(info, 1))
			var actual []byte
			var err error
			if retry {
				actual, err = RetryConfirmation(hashFunc, first, hrr)
			} else {
				actual, err = context.Confirmation(hashFunc, final)
			}
			require.NoError(t, err)
			require.Equal(t, expand.Sum(nil)[:8], actual)
		}
	}
}
