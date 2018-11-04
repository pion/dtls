package dtls

import (
	"reflect"
	"testing"
)

func TestExtensionSupportedGroups(t *testing.T) {
	rawSupportedGroups := []byte{0x0, 0xa, 0x0, 0x4, 0x0, 0x2, 0x0, 0x17}
	parsedSupportedGroups := &extensionSupportedGroups{
		supportedGroups: []namedCurve{namedCurveP256},
	}

	raw, err := parsedSupportedGroups.marshal()
	if err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(raw, rawSupportedGroups) {
		t.Errorf("extensionSupportedGroups marshal: got %#v, want %#v", raw, rawSupportedGroups)
	}
}
