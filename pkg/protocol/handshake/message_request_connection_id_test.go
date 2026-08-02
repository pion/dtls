// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageRequestConnectionID(t *testing.T) {
	message := &MessageRequestConnectionID{NumCIDs: 42}

	raw, err := message.Marshal()
	require.NoError(t, err)
	assert.Equal(t, []byte{42}, raw)
	assert.Equal(t, TypeRequestConnectionID, message.Type())

	decoded := &MessageRequestConnectionID{}
	require.NoError(t, decoded.Unmarshal(raw))
	assert.Equal(t, message, decoded)
}

func TestMessageRequestConnectionIDUnmarshalErrors(t *testing.T) {
	message := &MessageRequestConnectionID{NumCIDs: 42}

	for _, raw := range [][]byte{nil, {0x01, 0x02}} {
		err := message.Unmarshal(raw)
		assert.Error(t, err)
		assert.Equal(t, uint8(42), message.NumCIDs)
	}
}
