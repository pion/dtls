package dtls

import (
	"reflect"
	"testing"
)

func TestExtensionSupportedPointFormats(t *testing.T) {

	rawExtensionSupportedPointFormats := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
	parsedExtensionSupportedPointFormats := &extensionSupportedPointFormats{
		pointFormats: []ellipticCurvePointFormat{ellipticCurvePointFormatUncompressed},
	}

	raw, err := parsedExtensionSupportedPointFormats.Marshal()
	if err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(raw, rawExtensionSupportedPointFormats) {
		t.Errorf("extensionSupportedPointFormats marshal: got %#v, want %#v", raw, rawExtensionSupportedPointFormats)
	}
}
