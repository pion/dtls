// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandshakeMessageFinished(t *testing.T) {
	rawFinished := []byte{
		0x01, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}
	parsedFinished := &MessageFinished{
		VerifyData: rawFinished,
	}

	c := &MessageFinished{}
	assert.NoError(t, c.Unmarshal(rawFinished))
	assert.Equal(t, parsedFinished, c)

	raw, err := c.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawFinished, raw)
}
