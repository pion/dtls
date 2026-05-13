// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func TestInnerPlaintextRoundTrip(t *testing.T) {
	inner := &InnerPlaintext{
		Content:  []byte{0x01, 0x02},
		RealType: protocol.ContentTypeApplicationData,
		Zeros:    2,
	}

	raw, err := inner.Marshal()
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02, 0x17, 0x00, 0x00}, raw)

	var roundTrip InnerPlaintext
	require.NoError(t, roundTrip.Unmarshal(raw))
	require.Equal(t, inner.Content, roundTrip.Content)
	require.Equal(t, inner.RealType, roundTrip.RealType)
	require.Equal(t, inner.Zeros, roundTrip.Zeros)
}

func TestInnerPlaintextAllowsEmptyContent(t *testing.T) {
	var inner InnerPlaintext
	require.NoError(t, inner.Unmarshal([]byte{byte(protocol.ContentTypeAlert)}))
	require.Empty(t, inner.Content)
	require.Equal(t, protocol.ContentTypeAlert, inner.RealType)
	require.Equal(t, uint(0), inner.Zeros)
}

func TestInnerPlaintextRejectsMissingContentType(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		{},
		{0x00},
		{0x00, 0x00},
	} {
		var inner InnerPlaintext
		require.ErrorIs(t, inner.Unmarshal(raw), errBufferTooSmall)
	}
}
