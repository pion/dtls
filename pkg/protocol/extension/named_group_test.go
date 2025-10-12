// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidNamedGroup(t *testing.T) {
	t.Run("Valid ECDHE groups", func(t *testing.T) {
		for _, g := range []NamedGroup{secp256R1, secp384r1, secp521r1, x25519, x448} {
			assert.True(t, IsValidNamedGroup(g))
		}
	})

	t.Run("Valid FFDHE groups", func(t *testing.T) {
		for _, g := range []NamedGroup{ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192} {
			assert.True(t, IsValidNamedGroup(g))
		}
	})

	t.Run("FFDHE private-use range", func(t *testing.T) {
		tests := []NamedGroup{
			NamedGroup(FFDHEPrivateStart),
			NamedGroup(FFDHEPrivateStart + 1),
			NamedGroup(FFDHEPrivateEnd),
		}

		for _, g := range tests {
			assert.True(t, IsValidNamedGroup(g))
		}
	})

	t.Run("ECDHE private-use range", func(t *testing.T) {
		tests := []NamedGroup{
			NamedGroup(ECDHEPrivateStart),
			NamedGroup(ECDHEPrivateStart + 1),
			NamedGroup(ECDHEPrivateEnd),
		}

		for _, g := range tests {
			assert.True(t, IsValidNamedGroup(g))
		}
	})

	t.Run("Invalid values", func(t *testing.T) {
		for _, g := range []NamedGroup{
			0x0000, // invalid
			0x0001, // not assigned
			0x01FB, // just below FFDHE private-use start
			0x0200, // just above FFDHE private-use end
			0xFDFF, // below ECDHE private-use start
		} {
			assert.False(t, IsValidNamedGroup(g))
		}
	})
}
