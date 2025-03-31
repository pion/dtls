// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandshakeMessageServerHelloDone(t *testing.T) {
	rawServerHelloDone := []byte{}
	parsedServerHelloDone := &MessageServerHelloDone{}

	c := &MessageServerHelloDone{}
	assert.NoError(t, c.Unmarshal(rawServerHelloDone))
	assert.Equal(t, parsedServerHelloDone, c)

	raw, err := c.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawServerHelloDone, raw)
}
