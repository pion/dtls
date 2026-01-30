// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package hash

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/fingerprint"
	"github.com/stretchr/testify/assert"
)

func TestHashAlgorithm_StringRoundtrip(t *testing.T) {
	for algo := range Algorithms() {
		if algo == Ed25519 || algo == None {
			continue
		}

		str := algo.String()
		hash1 := algo.CryptoHash()
		hash2, err := fingerprint.HashFromString(str)
		assert.NoError(t, err)
		assert.Equal(t, hash1, hash2)
	}
}
