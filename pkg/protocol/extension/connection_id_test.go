// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"reflect"
	"testing"
)

func TestExtensionConnectionID(t *testing.T) {
	rawExtensionConnectionID := []byte{1, 6, 8, 3, 88, 12, 2, 47}
	parsedExtensionConnectionID := &ConnectionID{
		CID: rawExtensionConnectionID,
	}

	raw, err := parsedExtensionConnectionID.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	roundtrip := &ConnectionID{}
	if err := roundtrip.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(roundtrip, parsedExtensionConnectionID) {
		t.Errorf("parsedExtensionConnectionID unmarshal: got %#v, want %#v", roundtrip, parsedExtensionConnectionID)
	}
}
