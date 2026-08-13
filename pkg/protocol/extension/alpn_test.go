// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/stretchr/testify/assert"
)

func TestALPNProtocolSelection(t *testing.T) {
	selectedProtocol, err := ALPNProtocolSelection([]string{"http/1.1", "spd/1"}, []string{"spd/1"})
	assert.NoError(t, err)
	assert.Equal(t, "spd/1", selectedProtocol)

	_, err = ALPNProtocolSelection([]string{"http/1.1"}, []string{"spd/1"})
	assert.ErrorIs(t, err, dtlserrors.ErrALPNNoAppProto)

	selectedProtocol, err = ALPNProtocolSelection([]string{"http/1.1", "spd/1"}, []string{})
	assert.NoError(t, err)
	assert.Empty(t, selectedProtocol)
}
