// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/stretchr/testify/assert"
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
			WantError: ErrInvalidPacketLength,
		},
		{
			Name:      "Packet declared invalid length",
			Data:      []byte{0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0xFF, 0x01},
			WantError: ErrInvalidPacketLength,
		},
	} {
		dtlsPkts, err := UnpackDatagram(test.Data)
		assert.ErrorIs(t, err, test.WantError)
		assert.Equal(t, test.Want, dtlsPkts, "UDP decode: %s", test.Name)
	}
}

func TestRecordLayerRoundTrip(t *testing.T) {
	for _, test := range []struct {
		Name               string
		Data               []byte
		Want               *RecordLayer
		WantMarshalError   error
		WantUnmarshalError error
	}{
		{
			Name: "Change Cipher Spec, single packet",
			Data: []byte{0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
			Want: &RecordLayer{
				Header: Header{
					ContentType:    protocol.ContentTypeChangeCipherSpec,
					Version:        protocol.Version{Major: 0xfe, Minor: 0xff},
					Epoch:          0,
					SequenceNumber: 18,
				},
				Content: &protocol.ChangeCipherSpec{},
			},
		},
	} {
		r := &RecordLayer{}
		assert.ErrorIs(t, r.Unmarshal(test.Data), test.WantUnmarshalError)
		assert.Equal(t, test.Want, r, "RecordLayer should match expected value after unmarshal")

		data, marshalErr := r.Marshal()
		assert.ErrorIs(t, marshalErr, test.WantMarshalError)
		assert.Equal(t, test.Data, data, "RecordLayer should match expected value after marshal")
	}
}
