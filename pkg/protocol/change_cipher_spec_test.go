// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChangeCipherSpecRoundTrip(t *testing.T) {
	c := ChangeCipherSpec{}
	raw, err := c.Marshal()
	assert.NoError(t, err)

	var cNew ChangeCipherSpec
	assert.NoError(t, cNew.Unmarshal(raw))
	assert.Equal(t, c, cNew)
}

func TestChangeCipherSpecInvalid(t *testing.T) {
	c := ChangeCipherSpec{}
	assert.ErrorIs(t, c.Unmarshal([]byte{0x00}), errInvalidCipherSpec)
}
