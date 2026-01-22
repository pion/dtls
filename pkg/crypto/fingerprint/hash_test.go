// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package fingerprint

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashFromString(t *testing.T) {
	t.Run("InvalidHashAlgorithm", func(t *testing.T) {
		_, err := HashFromString("invalid-hash-algorithm")
		assert.ErrorIs(t, err, errInvalidHashAlgorithm)
	})
	t.Run("ValidHashAlgorithm", func(t *testing.T) {
		h, err := HashFromString("sha-512")
		assert.NoError(t, err)
		assert.Equal(t, h, crypto.SHA512)
	})
	t.Run("ValidCaseInsensitiveHashAlgorithm", func(t *testing.T) {
		h, err := HashFromString("SHA-512")
		assert.NoError(t, err)
		assert.Equal(t, h, crypto.SHA512)
	})
}

func TestStringFromHash_Roundtrip(t *testing.T) {
	for _, h := range nameToHash() {
		s, err := StringFromHash(h)
		assert.NoError(t, err)

		h2, err := HashFromString(s)
		assert.NoError(t, err)
		assert.Equal(t, h, h2)
	}
}
