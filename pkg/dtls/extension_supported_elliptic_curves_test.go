package dtls

import (
	"reflect"
	"testing"
)

func TestExtensionSupportedGroups(t *testing.T) {
	rawSupportedGroups := []byte{0x0, 0xa, 0x0, 0x4, 0x0, 0x2, 0x0, 0x1d}
	parsedSupportedGroups := &extensionSupportedEllipticCurves{
		ellipticCurves: []namedCurve{namedCurveX25519},
	}

	raw, err := parsedSupportedGroups.Marshal()
	if err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(raw, rawSupportedGroups) {
		t.Errorf("extensionSupportedGroups marshal: got %#v, want %#v", raw, rawSupportedGroups)
	}
}
