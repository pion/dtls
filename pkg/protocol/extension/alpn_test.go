// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/stretchr/testify/assert"
)

func TestALPN(t *testing.T) {
	extension := ALPN{
		ProtocolNameList: []string{"http/1.1", "spdy/1", "spdy/2", "spdy/3"}, //nolint:goconst
	}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	newExtension := ALPN{}
	assert.NoError(t, newExtension.Unmarshal(raw))
	assert.Equal(t, extension.ProtocolNameList, newExtension.ProtocolNameList)
}

func TestALPNProtocolSelection(t *testing.T) {
	selectedProtocol, err := ALPNProtocolSelection([]string{"http/1.1", "spd/1"}, []string{"spd/1"}) //nolint:goconst
	assert.NoError(t, err)
	assert.Equal(t, "spd/1", selectedProtocol)

	_, err = ALPNProtocolSelection([]string{"http/1.1"}, []string{"spd/1"})
	assert.ErrorIs(t, err, dtlserrors.ErrALPNNoAppProto)

	selectedProtocol, err = ALPNProtocolSelection([]string{"http/1.1", "spd/1"}, []string{})
	assert.NoError(t, err)
	assert.Empty(t, selectedProtocol)
}

func FuzzALPNUnmarshal(f *testing.F) {
	testCases := [][]byte{
		{
			0x00, 0x10, // Extension type
			0x00, 0x04, // Extension length
			0x00, 0x02, // ALPN length
			0x00, // ALPN length
			0x00, // ALPN
		},
		{
			0x00, 0x10, // Extension type
			0x00, 0x04, // Extension length
			0x00, 0x02, // ALPN list length
			0x01, // ALPN length
			0x41, // ALPN
		},
		{
			0x00, 0x10, // Extension type
			0x00, 0x06, // Extension length
			0x00, 0x0a, // ALPN list length
			0x01, // ALPN length
			0x41, // ALPN
			0x01, // ALPN length
			0x42, // ALPN
			0x42, // ALPN
			0x42, // ALPN
			0x42, // ALPN
			0x42, // ALPN
		},
	}
	for _, tc := range testCases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		alpn := ALPN{}
		err := alpn.Unmarshal(data)
		if err != nil {
			return
		}
		length := len(alpn.ProtocolNameList)
		assert.NotZero(t, length)

		for _, s := range alpn.ProtocolNameList {
			assert.NotZero(t, len(s))
		}
		testExtDataLength(t, &alpn, data, true)
	})
}
