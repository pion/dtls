package dtls

import (
	"reflect"
	"testing"
)

func TestUDPDecode(t *testing.T) {
	for _, test := range []struct {
		Name      string
		Data      []byte
		Want      [][]byte
		WantError error
	}{
		{
			Name: "Change Cipher Spec, single packet",
			Data: []byte{0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
			Want: [][]byte{
				{0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
			},
		},
		{
			Name: "Change Cipher Spec, multi packet",
			Data: []byte{
				0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
				0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01,
			},
			Want: [][]byte{
				{0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
				{0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01},
			},
		},

		{
			Name:      "Invalid packet length",
			Data:      []byte{0x14, 0xfe},
			WantError: errDTLSPacketInvalidLength,
		},
	} {
		dtlsPkts, err := unpackDatagram(test.Data)
		if err != test.WantError {
			t.Errorf("Unexpected Error %q: exp: %v got: %v", test.Name, test.WantError, err)
		} else if !reflect.DeepEqual(test.Want, dtlsPkts) {
			t.Errorf("%q UDP decode: got %q, want %q", test.Name, dtlsPkts, test.Want)
		}
	}
}

func TestRecordLayerRoundTrip(t *testing.T) {
	for _, test := range []struct {
		Name               string
		Data               []byte
		Want               *recordLayer
		WantMarshalError   error
		WantUnmarshalError error
	}{
		{
			Name: "Change Cipher Spec, single packet",
			Data: []byte{0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
			Want: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					contentType:     contentTypeChangeCipherSpec,
					protocolVersion: protocolVersion{0xfe, 0xff},
					epoch:           0,
					sequenceNumber:  18,
				},
				content: &changeCipherSpec{},
			},
		},
	} {
		r := &recordLayer{}
		if err := r.Unmarshal(test.Data); err != test.WantUnmarshalError {
			t.Errorf("Unexpected Error %q: exp: %v got: %v", test.Name, test.WantUnmarshalError, err)
		} else if !reflect.DeepEqual(test.Want, r) {
			t.Errorf("%q recordLayer.unmarshal: got %q, want %q", test.Name, r, test.Want)
		}

		data, marshalErr := r.Marshal()
		if marshalErr != test.WantMarshalError {
			t.Errorf("Unexpected Error %q: exp: %v got: %v", test.Name, test.WantMarshalError, marshalErr)
		} else if !reflect.DeepEqual(test.Data, data) {
			t.Errorf("%q recordLayer.marshal: got % 02x, want % 02x", test.Name, data, test.Data)
		}
	}
}
