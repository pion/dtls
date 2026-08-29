// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageNewConnectionID(t *testing.T) {
	message := &MessageNewConnectionID{
		CIDs:  [][]byte{{0x01, 0x02}, {}, {0x03}},
		Usage: ConnectionIDSpare,
	}
	want := []byte{
		0x00, 0x06, // cids length
		0x02, 0x01, 0x02,
		0x00,
		0x01, 0x03,
		0x01, // cid_spare
	}

	raw, err := message.Marshal()
	require.NoError(t, err)
	assert.Equal(t, want, raw)
	assert.Equal(t, TypeNewConnectionID, message.Type())

	decoded := &MessageNewConnectionID{}
	require.NoError(t, decoded.Unmarshal(raw))
	assert.Equal(t, message, decoded)
}

func TestMessageNewConnectionIDEmptyList(t *testing.T) {
	message := &MessageNewConnectionID{Usage: ConnectionIDImmediate}

	raw, err := message.Marshal()
	require.NoError(t, err)
	assert.Equal(t, []byte{0x00, 0x00, 0x00}, raw)

	decoded := &MessageNewConnectionID{}
	require.NoError(t, decoded.Unmarshal(raw))
	assert.Empty(t, decoded.CIDs)
}

func TestMessageNewConnectionIDMarshalErrors(t *testing.T) {
	tests := map[string]*MessageNewConnectionID{"CID too long": {CIDs: [][]byte{make([]byte, 256)}}, "CID list too long": {CIDs: make([][]byte, 65536)}, "invalid usage": {Usage: 2}}

	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			raw, err := message.Marshal()
			assert.Error(t, err)
			assert.Nil(t, raw)
		})
	}
}

func TestMessageNewConnectionIDUnmarshalErrors(t *testing.T) {
	tests := map[string][]byte{"too short": {0x00, 0x00}, "list length mismatch": {0x00, 0x01, 0x00}, "CID length mismatch": {0x00, 0x02, 0x02, 0xaa, 0x00}, "invalid usage": {0x00, 0x00, 0x02}}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			message := &MessageNewConnectionID{
				CIDs:  [][]byte{{0xff}},
				Usage: ConnectionIDSpare,
			}
			err := message.Unmarshal(raw)
			assert.Error(t, err)
			assert.Equal(t, [][]byte{{0xff}}, message.CIDs)
			assert.Equal(t, ConnectionIDSpare, message.Usage)
		})
	}

	assert.ErrorIs(t, (&MessageNewConnectionID{}).Unmarshal([]byte{0x00, 0x00}), dtlserrors.ErrBufferTooSmall)
}
