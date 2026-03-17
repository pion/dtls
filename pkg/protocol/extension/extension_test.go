// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"encoding/binary"
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

// testExtDataLength is used to check the declared length in an extension and
// should only be called after a succesfull unmarshal.
func testExtDataLength(t *testing.T, ext Extension, data []byte) {
	t.Helper()
	// [2 type][2 length][...value...]
	if len(data) < 4 {
		assert.Fail(t, "Unmarshal succeeded with fewer than 4 bytes")
	}
	declaredLength := int(binary.BigEndian.Uint16(data[2:4]))
	extensionEnd := 4 + declaredLength

	// The extension data window must not overflow the buffer.
	if extensionEnd > len(data) {
		assert.Failf(t, "Overflow",
			"Unmarshal succeeded but declared length %d overflows buffer of size %d. Data: %x",
			declaredLength, len(data), data)

		return
	}

	// If the round-trip produces different bytes, Unmarshal consumed
	// something it shouldn't have (or ignored bytes within the window).
	enc, err := ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, data[:extensionEnd], enc,
		"Round-trip mismatch: Unmarshal consumed bytes outside declared extension window")
}
