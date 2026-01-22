// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/stretchr/testify/assert"
)

func TestExtensionSupportedGroups(t *testing.T) {
	rawSupportedGroups := []byte{0x0, 0xa, 0x0, 0x4, 0x0, 0x2, 0x0, 0x1d}
	parsedSupportedGroups := &SupportedEllipticCurves{
		EllipticCurves: []elliptic.Curve{elliptic.X25519},
	}

	raw, err := parsedSupportedGroups.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawSupportedGroups, raw)

	roundtrip := &SupportedEllipticCurves{}
	assert.NoError(t, roundtrip.Unmarshal(raw))
	assert.Equal(t, parsedSupportedGroups, roundtrip)
}
