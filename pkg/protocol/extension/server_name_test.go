// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServerName(t *testing.T) {
	extension := ServerName{ServerName: "test.domain"}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	newExtension := ServerName{}
	assert.NoError(t, newExtension.Unmarshal(raw))
	assert.Equal(t, extension.ServerName, newExtension.ServerName)
}
