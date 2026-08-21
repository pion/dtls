// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReturnRoutabilityCheck(t *testing.T) {
	want := ReturnRoutabilityCheck{
		MessageType: ReturnRoutabilityCheckPathResponse,
		Cookie:      [ReturnRoutabilityCheckCookieLength]byte{1, 2, 3, 4, 5, 6, 7, 8},
	}

	raw, err := want.Marshal()
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 1, 2, 3, 4, 5, 6, 7, 8}, raw)

	var got ReturnRoutabilityCheck
	require.NoError(t, got.Unmarshal(raw))
	assert.Equal(t, want, got)
	assert.Equal(t, ContentTypeReturnRoutabilityCheck, got.ContentType())
}

func TestReturnRoutabilityCheckUnmarshal(t *testing.T) {
	tests := map[string]struct {
		raw         []byte
		expectedErr error
	}{
		"Empty":       {raw: nil, expectedErr: dtlserrors.ErrBufferTooSmall},
		"ShortKnown":  {raw: []byte{byte(ReturnRoutabilityCheckPathChallenge)}, expectedErr: dtlserrors.ErrLengthMismatch},
		"LongKnown":   {raw: make([]byte, 10), expectedErr: dtlserrors.ErrLengthMismatch},
		"UnknownType": {raw: []byte{42, 1, 2, 3}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var message ReturnRoutabilityCheck
			err := message.Unmarshal(test.raw)
			assert.ErrorIs(t, err, test.expectedErr)
		})
	}
}
