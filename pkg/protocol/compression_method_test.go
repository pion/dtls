// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeCompressionMethods(t *testing.T) {
	testCases := []struct {
		buf    []byte
		result []*CompressionMethod
		err    error
	}{
		{[]byte{}, nil, errBufferTooSmall},
	}

	for _, testCase := range testCases {
		_, err := DecodeCompressionMethods(testCase.buf)
		assert.ErrorIs(t, err, testCase.err)
	}
}
