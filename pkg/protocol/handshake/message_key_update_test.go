// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageKeyUpdate(t *testing.T) {
	for _, request := range []KeyUpdateRequest{KeyUpdateNotRequested, KeyUpdateRequested} {
		message := &MessageKeyUpdate{RequestUpdate: request}

		raw, err := message.Marshal()
		require.NoError(t, err)
		assert.Equal(t, []byte{byte(request)}, raw)
		assert.Equal(t, TypeKeyUpdate, message.Type())

		decoded := &MessageKeyUpdate{}
		require.NoError(t, decoded.Unmarshal(raw))
		assert.Equal(t, message, decoded)
	}
}

func TestMessageKeyUpdateErrors(t *testing.T) {
	raw, err := (&MessageKeyUpdate{RequestUpdate: 2}).Marshal()
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidKeyUpdate)
	assert.Nil(t, raw)

	message := &MessageKeyUpdate{RequestUpdate: KeyUpdateRequested}
	for _, raw := range [][]byte{nil, {0x00, 0x00}, {0x02}} {
		err = message.Unmarshal(raw)
		assert.Error(t, err)
		assert.Equal(t, KeyUpdateRequested, message.RequestUpdate)
	}
}
