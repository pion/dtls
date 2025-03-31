// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestALPN(t *testing.T) {
	extension := ALPN{
		ProtocolNameList: []string{"http/1.1", "spdy/1", "spdy/2", "spdy/3"},
	}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	newExtension := ALPN{}
	assert.NoError(t, newExtension.Unmarshal(raw))
	assert.Equal(t, extension.ProtocolNameList, newExtension.ProtocolNameList)
}

func TestALPNProtocolSelection(t *testing.T) {
	selectedProtocol, err := ALPNProtocolSelection([]string{"http/1.1", "spd/1"}, []string{"spd/1"})
	assert.NoError(t, err)
	assert.Equal(t, "spd/1", selectedProtocol)

	_, err = ALPNProtocolSelection([]string{"http/1.1"}, []string{"spd/1"})
	assert.ErrorIs(t, err, errALPNNoAppProto)

	selectedProtocol, err = ALPNProtocolSelection([]string{"http/1.1", "spd/1"}, []string{})
	assert.NoError(t, err)
	assert.Empty(t, selectedProtocol)
}
