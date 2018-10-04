package main

import (
	"reflect"
	"testing"
)

func TestUDPDecode(t *testing.T) {
	for _, test := range []struct {
		Name      string
		Data      []byte
		Want      []*recordLayer
		WantError error
	}{
		{
			Name: "Change Cipher Spec, single packet",
			Data: []byte{0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
			Want: []*recordLayer{&recordLayer{
				protocolVersion: protocolVersion{0xfe, 0xff},
				epoch:           0,
				sequenceNumber:  18,
				content:         &changeCipherSpec{},
			}},
		},
	} {
		dtlsPkts, err := decodeUDPPacket(test.Data)
		if err != nil {
			t.Errorf("Unmarshal %q: %v", test.Name, err)
		} else if !reflect.DeepEqual(test.Want, dtlsPkts) {
			t.Errorf("%q UDP decode: got %q, want %q", test.Name, dtlsPkts, test.Want)
		}
	}
}
