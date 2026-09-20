// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/require"
)

func TestFixedRecordCodec(t *testing.T) {
	for _, cid := range [][]byte{nil, {0xca, 0xfe}} {
		config := recordlayer.RecordConfig{ContentType: protocol.ContentTypeApplicationData, Version: protocol.Version1_2, Epoch: 0x1234, SequenceNumber: 0x010203040506, ConnectionID: cid}
		if len(cid) > 0 {
			config.ContentType = protocol.ContentTypeConnectionID
		}
		payload := []byte{0xaa, 0xbb}
		raw, err := recordlayer.MarshalRecord(config, payload)
		require.NoError(t, err)
		want := []byte{byte(config.ContentType), 0xfe, 0xfd, 0x12, 0x34, 1, 2, 3, 4, 5, 6}
		want = append(want, cid...)
		want = append(want, 0, 2, 0xaa, 0xbb)
		require.Equal(t, want, raw)
		parsed, err := recordlayer.ParseRecord(raw, len(cid))
		require.NoError(t, err)
		require.False(t, parsed.IsUnified())
		require.Equal(t, config.ContentType, parsed.ContentType())
		require.Equal(t, config.Version, parsed.Version())
		require.Equal(t, config.Epoch, parsed.Epoch())
		require.Equal(t, config.SequenceNumber, parsed.SequenceNumber())
		require.Equal(t, 6, parsed.SequenceBytes())
		require.Equal(t, cid, parsed.ConnectionID())
		require.True(t, parsed.LengthPresent())
		require.Equal(t, payload, parsed.Payload())
		require.Equal(t, want[:len(want)-2], parsed.HeaderBytes())
		// The encoder owns its output, while the parser borrows that output.
		payload[0] ^= 0xff
		require.Equal(t, byte(0xaa), parsed.Payload()[0])
		raw[len(raw)-1] ^= 0xff
		require.Equal(t, raw[len(raw)-1], parsed.Payload()[1])
		for _, bad := range [][]byte{raw[:len(raw)-1], append(bytes.Clone(raw), 0)} {
			got, err := recordlayer.ParseRecord(bad, len(cid))
			require.Error(t, err)
			require.Empty(t, got.Raw())
		}
	}
}

func TestFixedRecordRejectsInvalidInputs(t *testing.T) {
	valid := recordlayer.RecordConfig{ContentType: protocol.ContentTypeApplicationData, Version: protocol.Version1_2}
	for _, mutate := range []func(*recordlayer.RecordConfig){
		func(c *recordlayer.RecordConfig) { c.SequenceNumber = recordlayer.MaxSequenceNumber + 1 },
		func(c *recordlayer.RecordConfig) { c.Version = protocol.Version1_3 },
		func(c *recordlayer.RecordConfig) { c.ContentType = 0 },
		func(c *recordlayer.RecordConfig) { c.ContentType = 0x20 },
		func(c *recordlayer.RecordConfig) { c.ContentType = protocol.ContentTypeConnectionID },
		func(c *recordlayer.RecordConfig) { c.ConnectionID = []byte{1} },
		func(c *recordlayer.RecordConfig) {
			c.ContentType = protocol.ContentTypeConnectionID
			c.ConnectionID = make([]byte, 256)
		},
	} {
		c := valid
		mutate(&c)
		raw, err := recordlayer.MarshalRecord(c, []byte{1})
		require.Error(t, err)
		require.Nil(t, raw)
	}
	raw, err := recordlayer.MarshalRecord(valid, make([]byte, 65536))
	require.ErrorIs(t, err, recordlayer.ErrInvalidPacketLength)
	require.Nil(t, raw)
	raw, err = recordlayer.MarshalRecord(recordlayer.RecordConfig{ContentType: protocol.ContentTypeConnectionID, Version: protocol.Version1_2, ConnectionID: []byte{1, 2}}, []byte{3})
	require.NoError(t, err)
	for _, n := range []int{-1, 0, 1, 3, 256} {
		parsed, err := recordlayer.ParseRecord(raw, n)
		require.Error(t, err)
		require.Empty(t, parsed.Raw())
	}
}

func FuzzHeaderCIDUnmarshal(f *testing.F) {
	for _, cid := range [][]byte{nil, {1, 2, 3, 4}} {
		c := recordlayer.RecordConfig{ContentType: protocol.ContentTypeApplicationData, Version: protocol.Version1_2, ConnectionID: cid}
		if len(cid) > 0 {
			c.ContentType = protocol.ContentTypeConnectionID
		}
		raw, err := recordlayer.MarshalRecord(c, []byte{1, 2, 3})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := recordlayer.ParseRecord(raw, 4)
		if err != nil || r.IsUnified() {
			return
		}
		encoded, err := recordlayer.MarshalRecord(recordlayer.RecordConfig{ContentType: r.ContentType(), Version: r.Version(), Epoch: r.Epoch(), SequenceNumber: r.SequenceNumber(), ConnectionID: r.ConnectionID()}, r.Payload())
		if r.ContentType() == 0 {
			require.Error(t, err)

			return
		}
		require.NoError(t, err)
		require.Equal(t, raw, encoded)
	})
}

func FuzzRecordLayer_MarshalScan_RoundTrip(f *testing.F) {
	f.Add([]byte{1}, uint16(0), uint64(0))
	f.Add([]byte{1, 2, 3}, uint16(1), uint64(5))
	f.Fuzz(func(t *testing.T, payload []byte, epoch uint16, sequence uint64) {
		if len(payload) == 0 {
			payload = []byte{0}
		}
		if len(payload) > 1<<14 {
			payload = payload[:1<<14]
		}
		raw, err := recordlayer.MarshalRecord(recordlayer.RecordConfig{ContentType: protocol.ContentTypeApplicationData, Version: protocol.Version1_2, Epoch: epoch, SequenceNumber: sequence}, payload)
		if sequence > recordlayer.MaxSequenceNumber {
			require.Error(t, err)

			return
		}
		require.NoError(t, err)
		records, err := recordlayer.UnpackDatagram(raw, recordlayer.UnpackDatagramConfig{})
		require.NoError(t, err)
		require.Len(t, records, 1)
		r, err := recordlayer.ParseRecord(records[0], 0)
		require.NoError(t, err)
		require.Equal(t, sequence, r.SequenceNumber())
		require.Equal(t, epoch, r.Epoch())
		require.Equal(t, payload, r.Payload())
	})
}

func FuzzRecordLayer_UnpackDatagram_RoundTrip(f *testing.F) {
	f.Add(uint8(1), []byte("a"), []byte{}, []byte{}, []byte{})
	f.Add(uint8(3), []byte("one"), []byte("two"), []byte("three"), []byte{})
	f.Fuzz(func(t *testing.T, n uint8, p1, p2, p3, p4 []byte) {
		payloads := [][]byte{p1, p2, p3, p4}
		payloads = payloads[:int(n%4)+1]
		var datagram []byte
		var want [][]byte
		for i, payload := range payloads {
			if len(payload) == 0 {
				payload = []byte{0}
			}
			if len(payload) > 1<<14 {
				payload = payload[:1<<14]
			}
			raw, err := recordlayer.MarshalRecord(recordlayer.RecordConfig{ContentType: protocol.ContentTypeApplicationData, Version: protocol.Version1_2, SequenceNumber: uint64(i)}, payload)
			require.NoError(t, err)
			datagram = append(datagram, raw...)
			want = append(want, raw)
		}
		records, err := recordlayer.UnpackDatagram(datagram, recordlayer.UnpackDatagramConfig{})
		require.NoError(t, err)
		require.Equal(t, want, records)
		records, err = recordlayer.UnpackDatagram(datagram[:len(datagram)-1], recordlayer.UnpackDatagramConfig{})
		require.ErrorIs(t, err, recordlayer.ErrInvalidPacketLength)
		require.Len(t, records, len(want)-1)
	})
}

func ExampleParseRecord() {
	raw, err := recordlayer.MarshalRecord(recordlayer.RecordConfig{ContentType: protocol.ContentTypeHandshake, Version: protocol.Version1_2}, []byte{1, 2, 3})
	if err != nil {
		panic(err)
	}
	records, err := recordlayer.UnpackDatagram(raw, recordlayer.UnpackDatagramConfig{})
	if err != nil {
		panic(err)
	}
	record, err := recordlayer.ParseRecord(records[0], 0)
	if err != nil {
		panic(err)
	}
	fmt.Printf("epoch=%d sequence=%d payload=%x\n", record.Epoch(), record.SequenceNumber(), record.Payload())
	// Output: epoch=0 sequence=0 payload=010203
}
