// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"encoding/binary"
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/recordwire"
	"github.com/pion/dtls/v4/pkg/protocol"
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
		{Name: "Change Cipher Spec, single packet", Data: []byte{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01}, Want: [][]byte{{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01}}},
		{
			Name: "Change Cipher Spec, multi packet",
			Data: []byte{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01, 0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01},
			Want: [][]byte{{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01}, {0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01}},
		},
		{
			Name:      "Invalid packet length",
			Data:      []byte{0x14, 0xfe},
			WantError: ErrInvalidPacketLength,
		},
		{Name: "Packet declared invalid length", Data: []byte{0x14, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0xFF, 0x01}, WantError: ErrInvalidPacketLength},
	} {
		dtlsPkts, err := UnpackDatagram(test.Data, UnpackDatagramConfig{})
		assert.ErrorIs(t, err, test.WantError)
		assert.Equal(t, test.Want, dtlsPkts, "UDP decode: %s", test.Name)
	}
}

func TestUnpackDatagramMixedFixedRecords(t *testing.T) {
	ordinaryFirst := []byte{byte(protocol.ContentTypeApplicationData), 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xa1}
	cidRecord := []byte{byte(protocol.ContentTypeConnectionID), 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xca, 0xfe, 0x00, 0x01, 0xb2}
	ordinaryLast := []byte{byte(protocol.ContentTypeAlert), 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0xc3}
	datagram := append([]byte{}, ordinaryFirst...)
	datagram = append(datagram, cidRecord...)
	datagram = append(datagram, ordinaryLast...)

	records, err := UnpackDatagram(datagram, UnpackDatagramConfig{CIDLength: 2})
	require.NoError(t, err)
	require.Equal(t, [][]byte{ordinaryFirst, cidRecord, ordinaryLast}, records)
	records[0][FixedHeaderSize] = 0xd4
	require.Equal(t, byte(0xd4), datagram[FixedHeaderSize])

	truncated := datagram[:len(datagram)-1]
	records, err = UnpackDatagram(truncated, UnpackDatagramConfig{CIDLength: 2})
	require.ErrorIs(t, err, ErrInvalidPacketLength)
	require.Len(t, records, 2)
	prefix := append([]byte{}, records[0]...)
	prefix = append(prefix, records[1]...)
	require.Equal(t, datagram[:len(ordinaryFirst)+len(cidRecord)], prefix)
}

func TestUnpackDatagramRejectsInvalidCIDLength(t *testing.T) {
	for _, cidLength := range []int{-1, maxConnectionIDLength + 1} {
		records, err := UnpackDatagram(nil, UnpackDatagramConfig{CIDLength: cidLength})
		require.ErrorIs(t, err, ErrInvalidPacketLength)
		require.Nil(t, records)
	}
}

func FuzzUnpackDatagram_No_Panics(f *testing.F) {
	Datasingle := []byte{
		0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
	}
	Datamulti := []byte{0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01, 0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01}
	f.Add(Datasingle, uint8(0))
	f.Add(Datamulti, uint8(0))
	f.Add(append([]byte{recordwire.UnifiedFixedBits, 0x01}, make([]byte, minDTLSCiphertextRecordLen)...), uint8(0))

	f.Fuzz(func(_ *testing.T, data []byte, cidLength uint8) {
		_, _ = UnpackDatagram(data, UnpackDatagramConfig{CIDLength: int(cidLength)})
	})
}

func FuzzRecordLayer_UnpackDatagramCID_RoundTrip(f *testing.F) {
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

			header[1], header[2] = protocol.Version1_2.Major(), protocol.Version1_2.Minor()
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

		parts, err := UnpackDatagram(data, UnpackDatagramConfig{CIDLength: cl})
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

			lenIdx := FixedHeaderSize - 2 + hdrExtra
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
			lenIdx := FixedHeaderSize - 2 + hdrExtra
			//nolint:gosec // The fuzz inputs are bounded
			binary.BigEndian.PutUint16(bad[lenIdx:], uint16(len(bad)))
			_, err = UnpackDatagram(bad, UnpackDatagramConfig{CIDLength: cl})
			require.ErrorIs(t, err, ErrInvalidPacketLength)
		}

		// Negative: truncate the datagram.
		if len(data) > 0 {
			_, err = UnpackDatagram(data[:len(data)-1], UnpackDatagramConfig{CIDLength: cl})
			require.ErrorIs(t, err, ErrInvalidPacketLength)
		}
	})
}

func ciphertext13Payload(seed byte) []byte {
	out := make([]byte, minDTLSCiphertextRecordLen)
	for i := range out {
		out[i] = seed + byte(i)
	}

	return out
}

func TestUnpackDatagramCiphertext13(t *testing.T) {
	encryptedRecord := ciphertext13Payload(0xaa)
	ciphertextWithLengthRaw, err := MarshalCiphertext(CiphertextConfig{SequenceNumber: 1, TwoByteSequence: true, LengthPresent: true}, encryptedRecord)
	require.NoError(t, err)

	ciphertextWithoutLengthRaw := append([]byte{0x20, 0x02}, ciphertext13Payload(0xcc)...)

	datagram := append(append([]byte{}, ciphertextWithLengthRaw...), ciphertextWithoutLengthRaw...)
	records, err := UnpackDatagram(datagram, UnpackDatagramConfig{})
	require.NoError(t, err)
	require.Equal(t, [][]byte{ciphertextWithLengthRaw, ciphertextWithoutLengthRaw}, records)
}

func TestUnpackDatagramRejectsShortFinalCiphertextRecordWithoutLength(t *testing.T) {
	for recordLen := range minDTLSCiphertextRecordLen {
		raw := append([]byte{0x20, 0x01}, make([]byte, recordLen)...)

		_, err := UnpackDatagram(raw, UnpackDatagramConfig{})
		require.ErrorIs(t, err, ErrInvalidPacketLength, "record length %d", recordLen)
	}
}

func TestUnpackDatagramRejectsShortCiphertextRecordWithLength(t *testing.T) {
	for recordLen := range minDTLSCiphertextRecordLen {
		raw := []byte{
			0x2c, 0x00, 0x01,
			byte(recordLen >> 8), byte(recordLen),
		}
		raw = append(raw, make([]byte, recordLen)...)

		_, err := UnpackDatagram(raw, UnpackDatagramConfig{})
		require.ErrorIs(t, err, ErrInvalidPacketLength, "record length %d", recordLen)
	}
}

func TestUnpackDatagramAutoTargetAppliesCIDPolicyByRecordForm(t *testing.T) {
	cid := []byte{0xca, 0xfe}
	fixedEpochZero := fixedRecordForScannerTest(t, protocol.ContentTypeHandshake, 0, 0xa1)
	cidlessUnified := unifiedRecordForScannerTest(t, nil, 1)
	cidUnified := unifiedRecordForScannerTest(t, cid, 2)
	config := UnpackDatagramConfig{
		CIDLength:   len(cid),
		CIDRequired: true,
	}

	records, err := UnpackDatagram(fixedEpochZero, config)
	require.NoError(t, err)
	require.Equal(t, [][]byte{fixedEpochZero}, records)

	datagram := append(append(append([]byte{}, fixedEpochZero...), cidlessUnified...), cidUnified...)
	records, err = UnpackDatagram(datagram, config)
	require.NoError(t, err)
	require.Equal(t, [][]byte{fixedEpochZero, cidlessUnified, cidUnified}, records)

	withoutCID := append(append([]byte{}, fixedEpochZero...), cidlessUnified...)
	records, err = UnpackDatagram(withoutCID, config)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidCiphertextHeader)
	require.Nil(t, records)

	fixedProtectedWithoutCID := fixedRecordForScannerTest(t, protocol.ContentTypeApplicationData, 1, 0xb2)
	datagram = append(append([]byte{}, fixedProtectedWithoutCID...), cidUnified...)
	records, err = UnpackDatagram(datagram, config)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidCiphertextHeader)
	require.Nil(t, records)
}

func TestUnpackDatagramTargetVersion12RejectsUnified(t *testing.T) {
	fixed := fixedRecordForScannerTest(t, protocol.ContentTypeAlert, 0, 0xa1)
	unified := unifiedRecordForScannerTest(t, nil, 1)
	datagram := append(append([]byte{}, fixed...), unified...)

	records, err := UnpackDatagram(datagram, UnpackDatagramConfig{
		TargetVersion: protocol.Version1_2,
	})
	require.Error(t, err)
	require.Equal(t, [][]byte{fixed}, records)
}

func TestUnpackDatagramTargetVersion13FixedRecordPolicy(t *testing.T) {
	alertRecord := fixedRecordForScannerTest(t, protocol.ContentTypeAlert, 0, 0xa1)
	handshakeRecord := fixedRecordForScannerTest(t, protocol.ContentTypeHandshake, 0, 0xb2)
	ackRecord := fixedRecordForScannerTest(t, protocol.ContentTypeACK, 0, 0xc3)
	unified := unifiedRecordForScannerTest(t, nil, 1)
	datagram := append(append(append(append([]byte{}, alertRecord...), handshakeRecord...), ackRecord...), unified...)

	records, err := UnpackDatagram(datagram, UnpackDatagramConfig{
		TargetVersion: protocol.Version1_3,
	})
	require.NoError(t, err)
	require.Equal(t, [][]byte{alertRecord, handshakeRecord, ackRecord, unified}, records)

	for _, test := range []struct {
		name        string
		contentType protocol.ContentType
		epoch       uint16
	}{
		{name: "application data", contentType: protocol.ContentTypeApplicationData, epoch: 0},
		{name: "nonzero plaintext epoch", contentType: protocol.ContentTypeAlert, epoch: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			disallowed := fixedRecordForScannerTest(t, test.contentType, test.epoch, 0xdd)
			records, err := UnpackDatagram(disallowed, UnpackDatagramConfig{
				TargetVersion: protocol.Version1_3,
			})
			require.Error(t, err)
			require.Empty(t, records)
		})
	}
}

func TestUnpackDatagramRejectsUnsupportedTargetVersion(t *testing.T) {
	record := fixedRecordForScannerTest(t, protocol.ContentTypeAlert, 0, 0xa1)

	for _, target := range []protocol.Version{
		protocol.Version1_0,
		protocol.Version(0x0102),
	} {
		records, err := UnpackDatagram(record, UnpackDatagramConfig{TargetVersion: target})
		require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
		require.Nil(t, records)
	}
}

func TestUnpackDatagramRejectsRequiredCIDWithoutLength(t *testing.T) {
	records, err := UnpackDatagram(nil, UnpackDatagramConfig{
		TargetVersion: protocol.Version1_3,
		CIDRequired:   true,
	})
	require.ErrorIs(t, err, ErrInvalidPacketLength)
	require.Nil(t, records)
}

func TestUnpackDatagramVersion13RequiresCIDPerDatagram(t *testing.T) {
	cid := []byte{0xca, 0xfe, 0xba, 0xbe}
	fixed := fixedRecordForScannerTest(t, protocol.ContentTypeHandshake, 0, 0xa1)
	cidless := unifiedRecordForScannerTest(t, nil, 1)
	withCID := unifiedRecordForScannerTest(t, cid, 2)
	config := UnpackDatagramConfig{
		TargetVersion: protocol.Version1_3,
		CIDLength:     len(cid),
		CIDRequired:   true,
	}

	datagram := append(append(append([]byte{}, fixed...), cidless...), withCID...)
	records, err := UnpackDatagram(datagram, config)
	require.NoError(t, err)
	require.Equal(t, [][]byte{fixed, cidless, withCID}, records)

	datagramWithoutCID := append(append([]byte{}, fixed...), cidless...)
	records, err = UnpackDatagram(datagramWithoutCID, config)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidCiphertextHeader)
	require.Nil(t, records)

	// DTLSPlaintext has no CID field. A peer may retransmit an epoch-zero
	// handshake record after the local endpoint has committed the negotiated
	// CID, so a plaintext-only datagram remains eligible.
	records, err = UnpackDatagram(fixed, config)
	require.NoError(t, err)
	require.Equal(t, [][]byte{fixed}, records)
}

func TestUnpackDatagramVersion12RequiresCIDAfterEpochZero(t *testing.T) {
	cid := []byte{0xca, 0xfe}
	config := UnpackDatagramConfig{
		TargetVersion: protocol.Version1_2,
		CIDLength:     len(cid),
		CIDRequired:   true,
	}

	protectedWithCID, err := MarshalRecord(RecordConfig{
		ContentType: protocol.ContentTypeConnectionID, Version: protocol.Version1_2,
		Epoch: 1, ConnectionID: cid,
	}, []byte{0xc3})
	require.NoError(t, err)

	epochZero := fixedRecordForScannerTest(t, protocol.ContentTypeHandshake, 0, 0xa1)
	datagram := append(append([]byte{}, epochZero...), protectedWithCID...)
	records, err := UnpackDatagram(datagram, config)
	require.NoError(t, err)
	require.Equal(t, [][]byte{epochZero, protectedWithCID}, records)

	protectedWithoutCID := fixedRecordForScannerTest(t, protocol.ContentTypeApplicationData, 1, 0xb2)
	records, err = UnpackDatagram(protectedWithoutCID, config)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidCiphertextHeader)
	require.Nil(t, records)

	records, err = UnpackDatagram(epochZero, config)
	require.NoError(t, err)
	require.Equal(t, [][]byte{epochZero}, records)
}

func TestUnpackDatagramAllowsCIDLessUnifiedWithConfiguredCIDLength(t *testing.T) {
	raw, err := MarshalCiphertext(CiphertextConfig{SequenceNumber: 1, TwoByteSequence: true, LengthPresent: true}, ciphertext13Payload(0xaa))
	require.NoError(t, err)

	records, err := UnpackDatagram(raw, UnpackDatagramConfig{CIDLength: 4})
	require.NoError(t, err)
	require.Equal(t, [][]byte{raw}, records)
}

func TestUnpackDatagramRejectsUnifiedCIDWithoutConfiguredLength(t *testing.T) {
	raw, err := MarshalCiphertext(CiphertextConfig{ConnectionID: []byte{1, 2, 3, 4}, SequenceNumber: 1, TwoByteSequence: true, LengthPresent: true}, ciphertext13Payload(0xaa))
	require.NoError(t, err)

	_, err = UnpackDatagram(raw, UnpackDatagramConfig{})
	require.ErrorIs(t, err, ErrInvalidPacketLength)
}

func TestUnpackDatagramRejectsTruncatedUnifiedCID(t *testing.T) {
	_, err := UnpackDatagram([]byte{0x30, 0x01, 0x02}, UnpackDatagramConfig{CIDLength: 4})
	require.ErrorIs(t, err, ErrInvalidPacketLength)
}

func TestUnpackDatagramDoesNotApplyCIDAssociationPolicy(t *testing.T) {
	firstRaw, err := MarshalCiphertext(CiphertextConfig{ConnectionID: []byte{1, 2, 3, 4}, SequenceNumber: 1, TwoByteSequence: true, LengthPresent: true}, ciphertext13Payload(0xaa))
	require.NoError(t, err)

	secondRaw, err := MarshalCiphertext(CiphertextConfig{ConnectionID: []byte{4, 3, 2, 1}, SequenceNumber: 2, TwoByteSequence: true, LengthPresent: true}, ciphertext13Payload(0xba))
	require.NoError(t, err)

	records, err := UnpackDatagram(
		append(append([]byte{}, firstRaw...), secondRaw...),
		UnpackDatagramConfig{CIDLength: 4},
	)
	require.NoError(t, err)
	require.Equal(t, [][]byte{firstRaw, secondRaw}, records)
}

func TestUnpackDatagramDoesNotApplyContentPolicy(t *testing.T) {
	raw, err := MarshalRecord(RecordConfig{ContentType: protocol.ContentTypeApplicationData, Version: protocol.Version1_2}, []byte{0xaa})
	require.NoError(t, err)

	records, err := UnpackDatagram(raw, UnpackDatagramConfig{})
	require.NoError(t, err)
	require.Equal(t, [][]byte{raw}, records)
}

func TestUnpackDatagramAllRecordForms(t *testing.T) {
	fixedRaw, err := MarshalRecord(RecordConfig{ContentType: protocol.ContentTypeAlert, Version: protocol.Version1_2}, []byte{1, 0})
	require.NoError(t, err)

	cid := []byte{0xca, 0xfe}
	cidRaw, err := MarshalRecord(RecordConfig{
		ContentType: protocol.ContentTypeConnectionID, Version: protocol.Version1_2,
		Epoch: 1, SequenceNumber: 2, ConnectionID: cid,
	}, []byte{0xb2})
	require.NoError(t, err)

	unifiedRaw, err := MarshalCiphertext(CiphertextConfig{ConnectionID: cid, SequenceNumber: 3, TwoByteSequence: true, LengthPresent: true}, ciphertext13Payload(0xc3))
	require.NoError(t, err)

	datagram := append(append(append([]byte{}, fixedRaw...), cidRaw...), unifiedRaw...)
	records, err := UnpackDatagram(datagram, UnpackDatagramConfig{CIDLength: len(cid)})
	require.NoError(t, err)
	require.Equal(t, [][]byte{fixedRaw, cidRaw, unifiedRaw}, records)

	records, err = UnpackDatagram(datagram, UnpackDatagramConfig{})
	require.ErrorIs(t, err, ErrInvalidPacketLength)
	require.Equal(t, [][]byte{fixedRaw}, records)

	records, err = UnpackDatagram(
		datagram[:len(datagram)-1],
		UnpackDatagramConfig{CIDLength: len(cid)},
	)
	require.ErrorIs(t, err, ErrInvalidPacketLength)
	require.Equal(t, [][]byte{fixedRaw, cidRaw}, records)
}

func TestUnpackDatagramOmittedUnifiedLengthConsumesRemainder(t *testing.T) {
	omitted := append([]byte{recordwire.UnifiedFixedBits, 0x01}, ciphertext13Payload(0xaa)...)

	following, err := MarshalRecord(RecordConfig{ContentType: protocol.ContentTypeApplicationData, Version: protocol.Version1_2}, []byte{0xbb})
	require.NoError(t, err)

	datagram := append(append([]byte{}, omitted...), following...)
	records, err := UnpackDatagram(datagram, UnpackDatagramConfig{})
	require.NoError(t, err)
	require.Equal(t, [][]byte{datagram}, records)
}

func fixedRecordForScannerTest(t *testing.T, contentType protocol.ContentType, epoch uint16, payload byte) []byte {
	t.Helper()
	raw, err := MarshalRecord(RecordConfig{ContentType: contentType, Version: protocol.Version1_2, Epoch: epoch}, []byte{payload})
	require.NoError(t, err)

	return raw
}

func unifiedRecordForScannerTest(t *testing.T, cid []byte, sequenceNumber uint8) []byte {
	t.Helper()
	raw, err := MarshalCiphertext(CiphertextConfig{ConnectionID: cid, SequenceNumber: uint16(sequenceNumber), TwoByteSequence: true, LengthPresent: true}, ciphertext13Payload(sequenceNumber))
	require.NoError(t, err)

	return raw
}
