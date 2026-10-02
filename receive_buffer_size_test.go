// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsnet "github.com/pion/dtls/v4/internal/net"
	"github.com/stretchr/testify/assert"
)

func TestWithReceiveBufferSizeValidation(t *testing.T) {
	for _, size := range []int{-1, 0, dtlsnet.MaxInboundDatagramSize + 1, 1 << 20} {
		_, err := buildConfig(WithReceiveBufferSize(size))
		assert.ErrorIs(t, err, dtlserrors.ErrInvalidReceiveBufferSize)
	}

	for _, size := range []int{minReceiveBufferSize, 16384, dtlsnet.MaxInboundDatagramSize} {
		config, err := buildConfig(WithReceiveBufferSize(size))
		assert.NoError(t, err)
		assert.Equal(t, size, config.ReceiveBufferSize)
	}
}
