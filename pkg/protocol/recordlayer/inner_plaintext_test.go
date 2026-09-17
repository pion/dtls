// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"math"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func TestInnerPlaintextRoundTrip(t *testing.T) {
	raw, err := MarshalInnerPlaintext([]byte{1, 2}, protocol.ContentTypeApplicationData, 2)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 0x17, 0, 0}, raw)
	content, typ, padding, err := ParseInnerPlaintext(raw)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2}, content)
	require.Equal(t, protocol.ContentTypeApplicationData, typ)
	require.Equal(t, 2, padding)
	raw[0] = 3
	require.Equal(t, byte(3), content[0])
}

func TestInnerPlaintextAllowsEmptyContent(t *testing.T) {
	raw, err := MarshalInnerPlaintext(nil, protocol.ContentTypeApplicationData, 0)
	require.NoError(t, err)
	content, typ, padding, err := ParseInnerPlaintext(raw)
	require.NoError(t, err)
	require.Empty(t, content)
	require.Equal(t, protocol.ContentTypeApplicationData, typ)
	require.Zero(t, padding)
}

func TestInnerPlaintextRejectsMissingContentType(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, {0}, {0, 0}} {
		content, typ, padding, err := ParseInnerPlaintext(raw)
		require.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)
		require.Nil(t, content)
		require.Zero(t, typ)
		require.Zero(t, padding)
	}
	_, err := MarshalInnerPlaintext([]byte{1}, 0, 0)
	require.Error(t, err)
}

func TestInnerPlaintextRejectsInvalidPadding(t *testing.T) {
	for _, n := range []int{-1, math.MaxInt, 65535} {
		raw, err := MarshalInnerPlaintext([]byte{1}, protocol.ContentTypeAlert, n)
		require.Error(t, err)
		require.Nil(t, raw)
	}
}
