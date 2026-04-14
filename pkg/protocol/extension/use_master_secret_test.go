// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension // nolint:dupl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUseMasterSecret(t *testing.T) {
	extension := UseExtendedMasterSecret{Supported: true}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x17, // extension type
		0x00, 0x00, // extension length
	}
	assert.Equal(t, expect, raw)

	newExtension := UseExtendedMasterSecret{}

	assert.NoError(t, newExtension.Unmarshal(expect))
	assert.Equal(t, extension.Supported, newExtension.Supported)
}

func TestUseMasterSecret_NonEmpty(t *testing.T) {
	raw := []byte{
		0x00, 0x17, // extension type
		0x00, 0x42, // extension length
	}
	newExtension := UseExtendedMasterSecret{}
	err := newExtension.Unmarshal(raw)

	assert.ErrorIs(t, err, errLengthMismatch)
}

func FuzzUseMasterSecretUnmarshal(f *testing.F) {
	testcases := [][]byte{
		{
			0x00, 0x17, // extension type
			0x00, 0x00, // extension length
		},
		{
			0x00, 0x17, // extension type
			0x00, 0x02, // extension length
			0x42, 0x42,
		},
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m := UseExtendedMasterSecret{}
		err := m.Unmarshal(data)
		if err != nil {
			return
		}
		testExtDataLength(t, &m, data, true)
	})
}
