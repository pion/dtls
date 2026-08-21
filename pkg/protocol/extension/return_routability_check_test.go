// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReturnRoutabilityCheckExtension(t *testing.T) {
	extension := ReturnRoutabilityCheck{}
	raw, err := extension.MarshalData()
	require.NoError(t, err)
	assert.Empty(t, raw)
	assert.Equal(t, TypeReturnRoutabilityCheck, extension.ExtensionType())

	require.NoError(t, extension.UnmarshalData(nil))
	assert.ErrorIs(t, extension.UnmarshalData([]byte{0}), dtlserrors.ErrLengthMismatch)
}
