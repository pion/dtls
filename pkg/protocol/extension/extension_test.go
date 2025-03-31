// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtensions(t *testing.T) {
	t.Run("Zero", func(t *testing.T) {
		extensions, err := Unmarshal([]byte{})
		assert.NoError(t, err)
		assert.Empty(t, extensions)
	})

	t.Run("Invalid", func(t *testing.T) {
		extensions, err := Unmarshal([]byte{0x00})
		assert.ErrorIs(t, err, errBufferTooSmall)
		assert.Empty(t, extensions)
	})
}
