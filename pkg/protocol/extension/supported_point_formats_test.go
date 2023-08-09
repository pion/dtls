// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"reflect"
	"testing"

	"github.com/pion/dtls/v2/pkg/crypto/elliptic"
)

func TestExtensionSupportedPointFormats(t *testing.T) {
	rawExtensionSupportedPointFormats := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
	parsedExtensionSupportedPointFormats := &SupportedPointFormats{
		PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
	}

	raw, err := parsedExtensionSupportedPointFormats.Marshal()
	if err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(raw, rawExtensionSupportedPointFormats) {
		t.Fatalf("extensionSupportedPointFormats marshal: got %#v, want %#v", raw, rawExtensionSupportedPointFormats)
	}

	roundtrip := &SupportedPointFormats{}
	if err := roundtrip.Unmarshal(raw); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(roundtrip, parsedExtensionSupportedPointFormats) {
		t.Errorf("extensionSupportedPointFormats unmarshal: got %#v, want %#v", roundtrip, parsedExtensionSupportedPointFormats)
	}
}
