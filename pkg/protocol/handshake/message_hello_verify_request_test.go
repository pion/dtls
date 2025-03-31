// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/stretchr/testify/assert"
)

func TestHandshakeMessageHelloVerifyRequest(t *testing.T) {
	rawHelloVerifyRequest := []byte{
		0xfe, 0xff, 0x14, 0x25, 0xfb, 0xee, 0xb3, 0x7c, 0x95, 0xcf, 0x00,
		0xeb, 0xad, 0xe2, 0xef, 0xc7, 0xfd, 0xbb, 0xed, 0xf7, 0x1f, 0x6c, 0xcd,
	}
	parsedHelloVerifyRequest := &MessageHelloVerifyRequest{
		Version: protocol.Version{Major: 0xFE, Minor: 0xFF},
		Cookie: []byte{
			0x25, 0xfb, 0xee, 0xb3, 0x7c, 0x95, 0xcf, 0x00, 0xeb, 0xad,
			0xe2, 0xef, 0xc7, 0xfd, 0xbb, 0xed, 0xf7, 0x1f, 0x6c, 0xcd,
		},
	}

	h := &MessageHelloVerifyRequest{}
	assert.NoError(t, h.Unmarshal(rawHelloVerifyRequest))
	assert.Equal(t, parsedHelloVerifyRequest, h)

	raw, err := h.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawHelloVerifyRequest, raw)
}
