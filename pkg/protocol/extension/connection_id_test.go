// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectionIDPayload(t *testing.T) {
	extension := ConnectionID{CID: []byte{1, 6, 8, 3, 88, 12, 2, 47}}

	data, err := extension.MarshalData()
	require.NoError(t, err)
	assert.Equal(t, append([]byte{8}, extension.CID...), data)

	var roundTrip ConnectionID
	require.NoError(t, roundTrip.UnmarshalData(data))
	assert.Equal(t, extension, roundTrip)
}

func TestConnectionIDPayloadErrors(t *testing.T) {
	var connectionID ConnectionID
	assert.ErrorIs(t, connectionID.UnmarshalData(nil), dtlserrors.ErrInvalidCIDFormat)
	assert.ErrorIs(t, connectionID.UnmarshalData([]byte{2, 1}), dtlserrors.ErrInvalidCIDFormat)
	assert.ErrorIs(t, connectionID.UnmarshalData([]byte{1, 1, 2}), dtlserrors.ErrLengthMismatch)

	_, err := (ConnectionID{CID: make([]byte, 256)}).MarshalData()
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidCIDFormat)
}

func FuzzConnectionIDPayloadUnmarshal(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{1, 0x42})

	f.Fuzz(func(t *testing.T, data []byte) {
		var connectionID ConnectionID
		if err := connectionID.UnmarshalData(data); err != nil {
			return
		}

		encoded, err := connectionID.MarshalData()
		require.NoError(t, err)
		assert.Equal(t, data, encoded)
	})
}
