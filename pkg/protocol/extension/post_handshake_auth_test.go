// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPostHandshakeAuth(t *testing.T) {
	extension := PostHandshakeAuth{Enabled: true}
	newExtension := PostHandshakeAuth{}

	testEmptyExtensionRoundTrip(
		t,
		extension.Marshal,
		[]byte{0x00, 0x31, 0x00, 0x00},
		newExtension.Unmarshal,
		func() {
			assert.Equal(t, extension.Enabled, newExtension.Enabled)
		},
	)
}

func TestPostHandshakeAuth_NonEmpty(t *testing.T) {
	newExtension := PostHandshakeAuth{}
	testEmptyExtensionNonEmpty(t, 0x00, 0x31, newExtension.Unmarshal)
}

func FuzzPostHandshakeAuthUnmarshal(f *testing.F) {
	fuzzEmptyExtensionUnmarshal(f, 0x00, 0x31, func() Extension {
		return &PostHandshakeAuth{}
	})
}
