// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite/types"
	"github.com/stretchr/testify/assert"
)

func TestHandshakeMessageClientKeyExchange(t *testing.T) {
	rawClientKeyExchange := []byte{
		0x20, 0x26, 0x78, 0x4a, 0x78, 0x70, 0xc1, 0xf9, 0x71, 0xea, 0x50, 0x4a, 0xb5, 0xbb, 0x00, 0x76,
		0x02, 0x05, 0xda, 0xf7, 0xd0, 0x3f, 0xe3, 0xf7, 0x4e, 0x8a, 0x14, 0x6f, 0xb7, 0xe0, 0xc0, 0xff,
		0x54,
	}
	parsedClientKeyExchange := &MessageClientKeyExchange{
		PublicKey:            rawClientKeyExchange[1:],
		KeyExchangeAlgorithm: types.KeyExchangeAlgorithmEcdhe,
	}

	c := &MessageClientKeyExchange{
		KeyExchangeAlgorithm: types.KeyExchangeAlgorithmEcdhe,
	}
	assert.NoError(t, c.Unmarshal(rawClientKeyExchange))
	assert.Equal(t, parsedClientKeyExchange, c)

	raw, err := c.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawClientKeyExchange, raw)
}
