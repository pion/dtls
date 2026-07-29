// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProtectedFlightParseFailureClientCertificateRequired(t *testing.T) {
	failure := protectedFlightParseFailure(dtlserrors.ErrClientCertificateRequired)
	require.NotNil(t, failure)
	require.NotNil(t, failure.alert)
	assert.Equal(t, alert.Fatal, failure.alert.Level)
	assert.Equal(t, alert.CertificateRequired, failure.alert.Description)
	assert.ErrorIs(t, failure.err, dtlserrors.ErrClientCertificateRequired)
}
