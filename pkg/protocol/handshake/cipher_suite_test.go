// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeCipherSuiteIDs(t *testing.T) {
	testCases := []struct {
		buf    []byte
		result []uint16
		err    error
	}{
		{[]byte{}, nil, errBufferTooSmall},
	}

	for _, testCase := range testCases {
		_, err := decodeCipherSuiteIDs(testCase.buf)
		assert.ErrorIs(t, err, testCase.err)
	}
}
