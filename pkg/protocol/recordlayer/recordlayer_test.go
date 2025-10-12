// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"encoding/binary"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			Data: []byte{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
			Want: [][]byte{
				{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
			},
		},
		{
			Name: "Change Cipher Spec, multi packet",
			Data: []byte{
				0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
				0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01,
			},
			Want: [][]byte{
				{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
				{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01},
			},
		},
		{
			Name:      "Invalid packet length",
			Data:      []byte{0x14, 0xfe},
			WantError: ErrInvalidPacketLength,
		},
		{
			Name:      "Packet declared invalid length",
			Data:      []byte{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0xFF, 0x01},
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
			Data: []byte{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01},
			Want: &RecordLayer{
				Header: Header{
					ContentType:    protocol.ContentTypeChangeCipherSpec,
					Version:        protocol.Version1_2,
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

func FuzzRecordLayer_Unmarshal_No_Panics(f *testing.F) {
	f.Add([]byte{
		0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
	})

	f.Fuzz(func(_ *testing.T, data []byte) {
		var r RecordLayer
		_ = r.Unmarshal(data)
	})
}

func FuzzUnpackDatagram_No_Panics(f *testing.F) {
	Datasingle := []byte{
		0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
	}
	Datamulti := []byte{
		0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
		0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01,
	}
	f.Add(Datasingle)
	f.Add(Datamulti)

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = UnpackDatagram(data)
	})
}

func FuzzRecordLayer_MarshalUnmarshal_RoundTrip(f *testing.F) {
	f.Add([]byte{}, uint16(0), uint64(0))
	f.Add([]byte{1, 2, 3}, uint16(1), uint64(5))

	f.Fuzz(func(t *testing.T, payload []byte, epoch uint16, seq uint64) {
		if len(payload) > 1<<14 {
			payload = payload[:1<<14]
		}

		recordLayer := &RecordLayer{
			Header: Header{
				ContentType:    protocol.ContentTypeApplicationData,
				Version:        protocol.Version1_2,
				Epoch:          epoch,
				SequenceNumber: seq,
			},
			Content: &protocol.ApplicationData{Data: payload},
		}

		raw, err := recordLayer.Marshal()
		require.NoError(t, err)

		var back RecordLayer
		require.NoError(t, back.Unmarshal(raw))

		require.Equal(t, recordLayer.Header.ContentType, back.Header.ContentType)
		require.Equal(t, recordLayer.Header.Version, back.Header.Version)
		require.Equal(t, recordLayer.Header.Epoch, back.Header.Epoch)
		require.Equal(t, recordLayer.Header.SequenceNumber, back.Header.SequenceNumber)

		bodyLen := len(raw) - back.Header.Size()
		appData, ok := back.Content.(*protocol.ApplicationData)
		require.True(t, ok)
		require.Equal(t, bodyLen, len(appData.Data))

		require.Equal(t, payload, appData.Data)

		raw2, err := back.Marshal()
		require.NoError(t, err)
		require.Equal(t, raw, raw2)
	})
}

func FuzzRecordLayer_UnpackDatagram_RoundTrip(f *testing.F) {
	f.Add(uint8(1), []byte("a"), []byte{}, []byte{}, []byte{})
	f.Add(uint8(3), []byte("one"), []byte("two"), []byte("three"), []byte(""))

	f.Fuzz(func(t *testing.T, n uint8, p1, p2, p3, p4 []byte) {
		count := int(n%4) + 1
		all := [][]byte{p1, p2, p3, p4}
		all = all[:count]

		for i := range all {
			if len(all[i]) > 1<<14 {
				all[i] = all[i][:1<<14]
			}
			if len(all[i]) == 0 {
				all[i] = []byte{0} // ensure a non-empty record
			}
		}

		var dat []byte
		want := make([][]byte, 0, count)
		for i := 0; i < count; i++ {
			rl := &RecordLayer{
				Header: Header{
					ContentType:    protocol.ContentTypeApplicationData,
					Version:        protocol.Version1_2,
					Epoch:          uint16(i),                //nolint:gosec // G115: i is bounded (<= 4)
					SequenceNumber: uint64(1000) + uint64(i), //nolint:gosec // G115: i is bounded (<= 4)
				},
				Content: &protocol.ApplicationData{Data: all[i]},
			}
			raw, err := rl.Marshal()
			require.NoError(t, err)
			dat = append(dat, raw...)
			want = append(want, raw)
		}

		chunks, err := UnpackDatagram(dat)
		require.NoError(t, err)
		require.Equal(t, len(want), len(chunks))

		for i := range chunks {
			require.Equal(t, want[i], chunks[i])

			require.True(t, len(chunks[i]) >= FixedHeaderSize+1)
			ln := int(binary.BigEndian.Uint16(chunks[i][11:]))
			require.Equal(t, ln, len(chunks[i])-FixedHeaderSize)

			var rl RecordLayer
			require.NoError(t, rl.Unmarshal(chunks[i]))
		}

		if len(dat) >= FixedHeaderSize+2 {
			bad := append([]byte{}, dat...)
			orig := binary.BigEndian.Uint16(bad[11:])
			binary.BigEndian.PutUint16(bad[11:], orig+1)
			_, err = UnpackDatagram(bad)
			require.ErrorIs(t, err, ErrInvalidPacketLength)
		}

		if len(dat) > 0 {
			_, err = UnpackDatagram(dat[:len(dat)-1])
			require.ErrorIs(t, err, ErrInvalidPacketLength)
		}
	})
}

func FuzzRecordLayer_ContentAwareUnpackDatagram_RoundTrip(f *testing.F) {
	f.Add(uint8(5), []byte("hello"), []byte("world"))
	f.Add(uint8(0), []byte{}, []byte("x"))

	f.Fuzz(func(t *testing.T, cidLen uint8, p1, p2 []byte) {
		cl := int(cidLen % 8)

		bound := func(b []byte) []byte {
			if len(b) > 1<<14 {
				b = b[:1<<14]
			}
			if len(b) == 0 {
				b = []byte{0}
			}

			return b
		}
		p1, p2 = bound(p1), bound(p2)

		cid := make([]byte, cl)
		for i := range cid {
			cid[i] = byte(i)
		}

		makeCIDRecord := func(epoch uint16, seq uint64, payload []byte) []byte {
			header := make([]byte, FixedHeaderSize-2) // 11 bytes before len
			if cl > 0 {
				header[0] = byte(protocol.ContentTypeConnectionID)
			} else {
				header[0] = byte(protocol.ContentTypeApplicationData)
			}

			header[1], header[2] = protocol.Version1_2.Major, protocol.Version1_2.Minor
			binary.BigEndian.PutUint16(header[3:], epoch)

			// 48-bit sequence number
			seq48 := seq & 0x0000ffffffffffff
			header[5] = byte((seq48 >> 40) & 0xff)
			header[6] = byte((seq48 >> 32) & 0xff)
			header[7] = byte((seq48 >> 24) & 0xff)
			header[8] = byte((seq48 >> 16) & 0xff)
			header[9] = byte((seq48 >> 8) & 0xff)
			header[10] = byte(seq48 & 0xff)

			out := make([]byte, 0, len(header)+cl+2+len(payload))
			out = append(out, header...)
			if cl > 0 {
				out = append(out, cid...)
			}

			//nolint:gosec // G115: payload <= 1<<14
			binary.BigEndian.PutUint16(out[len(out):len(out)+2], uint16(len(payload)))
			out = out[:len(out)+2]
			out = append(out, payload...)

			return out
		}

		raw1 := makeCIDRecord(0, 10, p1)
		raw2 := makeCIDRecord(1, 11, p2)
		data := append(append([]byte{}, raw1...), raw2...)

		parts, err := ContentAwareUnpackDatagram(data, cl)
		require.NoError(t, err)
		require.Equal(t, 2, len(parts))
		require.Equal(t, raw1, parts[0])
		require.Equal(t, raw2, parts[1])

		// Validate length field and header size per record.
		for _, part := range parts {
			hdrExtra := 0
			if protocol.ContentType(part[0]) == protocol.ContentTypeConnectionID {
				hdrExtra = cl
			}

			require.GreaterOrEqual(t, len(part), FixedHeaderSize+hdrExtra)

			lenIdx := fixedHeaderLenIdx + hdrExtra
			require.GreaterOrEqual(t, len(part), lenIdx+2)

			decl := int(binary.BigEndian.Uint16(part[lenIdx:]))
			require.Equal(t, decl, len(part)-(FixedHeaderSize+hdrExtra))
		}

		// Negative: corrupt the first record's length.
		{
			bad := append([]byte{}, data...)
			hdrExtra := 0
			if protocol.ContentType(bad[0]) == protocol.ContentTypeConnectionID {
				hdrExtra = cl
			}
			lenIdx := fixedHeaderLenIdx + hdrExtra
			orig := binary.BigEndian.Uint16(bad[lenIdx:])
			binary.BigEndian.PutUint16(bad[lenIdx:], orig+1)
			_, err = ContentAwareUnpackDatagram(bad, cl)
			require.ErrorIs(t, err, ErrInvalidPacketLength)
		}

		// Negative: truncate the datagram.
		if len(data) > 0 {
			_, err = ContentAwareUnpackDatagram(data[:len(data)-1], cl)
			require.ErrorIs(t, err, ErrInvalidPacketLength)
		}
	})
}
