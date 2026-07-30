// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUseMasterSecret(t *testing.T) {
	extension := UseExtendedMasterSecret{Supported: true}
	newExtension := UseExtendedMasterSecret{}

	testEmptyExtensionRoundTrip(
		t,
		extension.Marshal,
		[]byte{0x00, 0x17, 0x00, 0x00},
		newExtension.Unmarshal,
		func() {
			assert.Equal(t, extension.Supported, newExtension.Supported)
		},
	)
}

func TestUseMasterSecret_NonEmpty(t *testing.T) {
	newExtension := UseExtendedMasterSecret{}
	testEmptyExtensionNonEmpty(t, 0x00, 0x17, newExtension.Unmarshal)
}

func FuzzUseMasterSecretUnmarshal(f *testing.F) {
	fuzzEmptyExtensionUnmarshal(f, 0x00, 0x17, func() Extension {
		return &UseExtendedMasterSecret{}
	})
}
