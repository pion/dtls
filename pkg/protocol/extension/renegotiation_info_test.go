// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenegotiationInfo(t *testing.T) {
	extension := RenegotiationInfo{RenegotiatedConnection: 0}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	newExtension := RenegotiationInfo{}
	assert.NoError(t, newExtension.Unmarshal(raw))
	assert.Equal(t, extension.RenegotiatedConnection, newExtension.RenegotiatedConnection)
}

func FuzzRenegotiationInfoUnmarshal(f *testing.F) {
	// Valid minimal encoding
	validCase := []byte{
		0xff, 0x01, // Extension type
		0x00, 0x01, // Extension length
		0x00, // RenegotiatedConnection
	}

	// Valid extension followed by extra bytes (e.g. a subsequent extension)
	withTrailing := []byte{
		0xff, 0x01, // Extension type
		0x00, 0x01, // Extension length (says 1 byte follows)
		0x00,       // RenegotiatedConnection
		0xde, 0xad, // Trailing data — should NOT be silently consumed
	}

	// Too short
	tooShort := []byte{0xff, 0x01, 0x00}

	testCases := [][]byte{
		validCase,
		withTrailing,
		tooShort,
	}
	for _, tc := range testCases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		ri := RenegotiationInfo{}
		err := ri.Unmarshal(data)
		if err != nil {
			return
		}

		// Invariant: if Unmarshal succeeded, the declared extension length
		// must not exceed the actual remaining bytes after the 4-byte header,
		// AND Unmarshal must not have silently skipped trailing bytes within
		// the extension boundary.
		//
		// Generic TLS extension layout: [2 type][2 length][...value...]
		// Any bytes beyond (4 + declaredLength) are the caller's concern,
		// but bytes *within* the extension window must be fully accounted for.
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

		// Re-marshal and compare against exactly the extension window.
		// If the round-trip produces different bytes, Unmarshal consumed
		// something it shouldn't have (or ignored bytes within the window).
		reEncoded, err := ri.Marshal()
		assert.NoError(t, err)
		assert.Equal(t, data[:extensionEnd], reEncoded,
			"Round-trip mismatch: Unmarshal consumed bytes outside declared extension window")
	})
}
