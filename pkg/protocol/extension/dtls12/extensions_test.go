// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls12

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtensionPayloads(t *testing.T) {
	tests := []struct {
		name  string
		value extension.Value
		wire  []byte
		out   extension.PayloadUnmarshaller
	}{
		{
			name: "point formats",
			value: SupportedPointFormats{PointFormats: []elliptic.CurvePointFormat{
				elliptic.CurvePointFormatUncompressed,
			}},
			wire: []byte{0x01, 0x00},
			out:  &SupportedPointFormats{},
		},
		{name: "extended master secret", value: ExtendedMasterSecret{}, wire: []byte{}, out: &ExtendedMasterSecret{}},
		{
			name:  "renegotiation info",
			value: RenegotiationInfo{RenegotiatedConnection: 7},
			wire:  []byte{7},
			out:   &RenegotiationInfo{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := test.value.MarshalData()
			require.NoError(t, err)
			assert.Equal(t, test.wire, data)
			require.NoError(t, test.out.UnmarshalData(data))
		})
	}
}

func TestExtensionPayloadErrors(t *testing.T) {
	assert.ErrorIs(t, (&SupportedPointFormats{}).UnmarshalData(nil), dtlserrors.ErrBufferTooSmall)
	assert.ErrorIs(t, (&SupportedPointFormats{}).UnmarshalData([]byte{2, 0}), dtlserrors.ErrLengthMismatch)
	assert.ErrorIs(t, (&ExtendedMasterSecret{}).UnmarshalData([]byte{0}), dtlserrors.ErrLengthMismatch)
	assert.ErrorIs(t, (&RenegotiationInfo{}).UnmarshalData(nil), dtlserrors.ErrLengthMismatch)

	_, err := (SupportedPointFormats{PointFormats: make([]elliptic.CurvePointFormat, 256)}).MarshalData()
	assert.ErrorIs(t, err, dtlserrors.ErrPointFormatsTooLarge)
}

func FuzzPayloadUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 0})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = (&SupportedPointFormats{}).UnmarshalData(data)
		_ = (&ExtendedMasterSecret{}).UnmarshalData(data)
		_ = (&RenegotiationInfo{}).UnmarshalData(data)
	})
}
