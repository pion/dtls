// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/stretchr/testify/assert"
)

func testEmptyExtensionRoundTrip(
	t *testing.T,
	marshal func() ([]byte, error),
	expect []byte,
	unmarshalInto func([]byte) error,
	assertEqual func(),
) {
	t.Helper()

	raw, err := marshal()
	assert.NoError(t, err)
	assert.Equal(t, expect, raw)
	assert.NoError(t, unmarshalInto(expect))
	assertEqual()
}

func testEmptyExtensionNonEmpty(t *testing.T, typeHi, typeLo byte, unmarshalInto func([]byte) error) {
	t.Helper()

	raw := []byte{typeHi, typeLo, 0x00, 0x42}
	err := unmarshalInto(raw)
	assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)
}

func fuzzEmptyExtensionUnmarshal(
	f *testing.F,
	typeHi, typeLo byte,
	newExt func() Extension,
) {
	f.Helper()

	testcases := [][]byte{
		{typeHi, typeLo, 0x00, 0x00},
		{typeHi, typeLo, 0x00, 0x02, 0x42, 0x42},
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ext := newExt()
		if err := ext.Unmarshal(data); err != nil {
			return
		}
		testExtDataLength(t, ext, data, true)
	})
}
