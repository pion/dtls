// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
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
