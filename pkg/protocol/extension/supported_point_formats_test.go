// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/stretchr/testify/assert"
)

func TestExtensionSupportedPointFormats(t *testing.T) {
	rawExtensionSupportedPointFormats := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
	parsedExtensionSupportedPointFormats := &SupportedPointFormats{
		PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
	}

	raw, err := parsedExtensionSupportedPointFormats.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawExtensionSupportedPointFormats, raw)

	roundtrip := &SupportedPointFormats{}
	assert.NoError(t, roundtrip.Unmarshal(raw))
	assert.Equal(t, parsedExtensionSupportedPointFormats, roundtrip)
}

func TestExtensionSupportedPointFormats_TooLong(t *testing.T) {
	pointFormats := make([]elliptic.CurvePointFormat, 256)
	_, err := (&SupportedPointFormats{PointFormats: pointFormats}).Marshal()
	assert.ErrorIs(t, err, errPointFormatsTooLarge)
}

func FuzzExtensionSupportedPointFormatsUnmarshal(f *testing.F) {
	tc := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
	f.Add(tc)

	f.Fuzz(func(t *testing.T, data []byte) {
		points := SupportedPointFormats{}
		err := points.Unmarshal(data)
		if err != nil {
			return
		}
		// Invalid point formats are filtered out
		testExtDataLength(t, &points, data, false)
	})
}
