// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/stretchr/testify/assert"
)

func TestDecodeCompressionMethods(t *testing.T) {
	testCases := []struct {
		buf    []byte
		result []*CompressionMethod
		err    error
	}{
		{[]byte{}, nil, dtlserrors.ErrBufferTooSmall},
	}

	for _, testCase := range testCases {
		_, err := DecodeCompressionMethods(testCase.buf)
		assert.ErrorIs(t, err, testCase.err)
	}
}
