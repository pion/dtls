// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"reflect"
	"testing"

	"github.com/pion/dtls/v2/pkg/crypto/elliptic"
)

func TestExtensionSupportedGroups(t *testing.T) {
	rawSupportedGroups := []byte{0x0, 0xa, 0x0, 0x4, 0x0, 0x2, 0x0, 0x1d}
	parsedSupportedGroups := &SupportedEllipticCurves{
		EllipticCurves: []elliptic.Curve{elliptic.X25519},
	}

	raw, err := parsedSupportedGroups.Marshal()
	if err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(raw, rawSupportedGroups) {
		t.Fatalf("extensionSupportedGroups marshal: got %#v, want %#v", raw, rawSupportedGroups)
	}

	roundtrip := &SupportedEllipticCurves{}
	if err := roundtrip.Unmarshal(raw); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(roundtrip, parsedSupportedGroups) {
		t.Errorf("extensionSupportedGroups unmarshal: got %#v, want %#v", roundtrip, parsedSupportedGroups)
	}
}
