// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

var errExample = errors.New("an example error")

func TestErrorUnwrap(t *testing.T) {
	err := fmt.Errorf("handshake failed: %w", errExample)

	assert.ErrorIs(t, err, errExample)
	assert.ErrorIs(t, errors.Unwrap(err), errExample)
}

func TestErrorNetError(t *testing.T) {
	err := temporaryNetworkError{err: errExample}

	var ne net.Error
	assert.ErrorAs(t, err, &ne)
	assert.ErrorIs(t, err, errExample)
	assert.False(t, ne.Timeout())
	assert.True(t, ne.Temporary()) //nolint:staticcheck
	assert.Equal(t, "an example error", ne.Error())
}
