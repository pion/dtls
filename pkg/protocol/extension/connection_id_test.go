// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtensionConnectionID(t *testing.T) {
	rawExtensionConnectionID := []byte{1, 6, 8, 3, 88, 12, 2, 47}
	parsedExtensionConnectionID := &ConnectionID{
		CID: rawExtensionConnectionID,
	}

	raw, err := parsedExtensionConnectionID.Marshal()
	assert.NoError(t, err)

	roundtrip := &ConnectionID{}
	assert.NoError(t, roundtrip.Unmarshal(raw))
	assert.Equal(t, parsedExtensionConnectionID, roundtrip)
}
