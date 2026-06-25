// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/require"
)

type oversizedPlaintextContent13 struct{}

func (oversizedPlaintextContent13) ContentType() protocol.ContentType {
	return protocol.ContentTypeAlert
}

func (oversizedPlaintextContent13) Marshal() ([]byte, error) {
	return make([]byte, maxDTLSPlaintextRecordLen+1), nil
}

func (oversizedPlaintextContent13) Unmarshal([]byte) error {
	return nil
}

func ciphertext13Payload(seed byte) []byte {
	out := make([]byte, minDTLSCiphertextRecordLen)
	for i := range out {
		out[i] = seed + byte(i)
	}

	return out
}

func TestPlaintextRecord13RoundTrip(t *testing.T) {
	record := &PlaintextRecord13{
		Header: Header{
			Version: protocol.Version1_2,
		},
		Content: &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify},
	}

	raw, err := record.Marshal()
	require.NoError(t, err)
	require.Equal(t, []byte{
		0x15, 0xfe, 0xfd,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x02,
		0x01, 0x00,
	}, raw)

	var roundTrip PlaintextRecord13
	require.NoError(t, roundTrip.Unmarshal(raw))
	require.Equal(t, protocol.ContentTypeAlert, roundTrip.Header.ContentType)
	require.Equal(t, protocol.Version1_2, roundTrip.Header.Version)
	require.Equal(t, uint16(0), roundTrip.Header.Epoch)
	require.Equal(t, uint16(2), roundTrip.Header.ContentLen)

	got, ok := roundTrip.Content.(*alert.Alert)
	require.True(t, ok)
	require.Equal(t, alert.Warning, got.Level)
	require.Equal(t, alert.CloseNotify, got.Description)
}

func TestPlaintextRecord13ACKRoundTrip(t *testing.T) {
	record := &PlaintextRecord13{
		Header: Header{
			Version: protocol.Version1_2,
		},
		Content: &protocol.ACK{
			Records: []protocol.RecordNumber{
				{Epoch: 2, SequenceNumber: 3},
			},
		},
	}

	raw, err := record.Marshal()
	require.NoError(t, err)
	require.Equal(t, protocol.ContentTypeACK, record.Header.ContentType)
	require.Equal(t, uint16(18), record.Header.ContentLen)

	var roundTrip PlaintextRecord13
	require.NoError(t, roundTrip.Unmarshal(raw))
	require.Equal(t, protocol.ContentTypeACK, roundTrip.Header.ContentType)

	got, ok := roundTrip.Content.(*protocol.ACK)
	require.True(t, ok)
	require.Equal(t, []protocol.RecordNumber{{Epoch: 2, SequenceNumber: 3}}, got.Records)
}

func TestPlaintextRecord13RejectsProtectedEpoch(t *testing.T) {
	record := &PlaintextRecord13{
		Header: Header{
			Version: protocol.Version1_2,
			Epoch:   1,
		},
		Content: &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify},
	}

	_, err := record.Marshal()
	require.ErrorIs(t, err, dtlserrors.ErrInvalidEpoch)
}

func TestPlaintextRecord13MarshalRejectsUnsupportedDTLS10Version(t *testing.T) {
	// RFC 9147 permits DTLS 1.0 only for initial-ClientHello compatibility,
	// but Pion does not support DTLS 1.0.
	record := &PlaintextRecord13{
		Header:  Header{Version: protocol.Version1_0},
		Content: &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify},
	}

	_, err := record.Marshal()
	require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
}

func TestPlaintextRecord13UnmarshalIgnoresLegacyRecordVersion(t *testing.T) {
	var roundTrip PlaintextRecord13
	err := roundTrip.Unmarshal([]byte{
		0x15, 0x01, 0x02,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x02,
		0x01, 0x00,
	})
	require.NoError(t, err)
	require.Equal(t, protocol.Version{Major: 0x01, Minor: 0x02}, roundTrip.Header.Version)

	got, ok := roundTrip.Content.(*alert.Alert)
	require.True(t, ok)
	require.Equal(t, alert.Warning, got.Level)
	require.Equal(t, alert.CloseNotify, got.Description)
}

func TestPlaintextRecord13AllowsDTLS10LegacyVersionForInitialClientHello(t *testing.T) {
	record := &PlaintextRecord13{
		Header: Header{Version: protocol.Version1_0},
		Content: &handshake.Handshake{
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				CompressionMethods: []*protocol.CompressionMethod{{}},
			},
		},
	}

	raw, err := record.Marshal()
	require.NoError(t, err)
	require.Equal(t, protocol.Version1_0, record.Header.Version)

	var roundTrip PlaintextRecord13
	require.NoError(t, roundTrip.Unmarshal(raw))

	gotHandshake, ok := roundTrip.Content.(*handshake.Handshake)
	require.True(t, ok)
	require.Equal(t, handshake.TypeClientHello, gotHandshake.Header.Type)
	require.Equal(t, uint16(0), gotHandshake.Header.MessageSequence)
	_, ok = gotHandshake.Message.(*handshake.MessageClientHello)
	require.True(t, ok)
}

func TestPlaintextRecord13MarshalRejectsDTLS10LegacyVersionForNonInitialClientHello(t *testing.T) {
	record := &PlaintextRecord13{
		Header: Header{Version: protocol.Version1_0},
		Content: &handshake.Handshake{
			Header: handshake.Header{MessageSequence: 1},
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				CompressionMethods: []*protocol.CompressionMethod{{}},
			},
		},
	}

	_, err := record.Marshal()
	require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
}

func TestPlaintextRecord13UnmarshalAcceptsDTLS10LegacyVersionForNonInitialClientHello(t *testing.T) {
	record := &PlaintextRecord13{
		Header: Header{Version: protocol.Version1_2},
		Content: &handshake.Handshake{
			Header: handshake.Header{MessageSequence: 1},
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				CompressionMethods: []*protocol.CompressionMethod{{}},
			},
		},
	}

	raw, err := record.Marshal()
	require.NoError(t, err)
	raw[1], raw[2] = protocol.Version1_0.Major, protocol.Version1_0.Minor

	var roundTrip PlaintextRecord13
	require.NoError(t, roundTrip.Unmarshal(raw))
	require.Equal(t, protocol.Version1_0, roundTrip.Header.Version)

	gotHandshake, ok := roundTrip.Content.(*handshake.Handshake)
	require.True(t, ok)
	require.Equal(t, handshake.TypeClientHello, gotHandshake.Header.Type)
	require.Equal(t, uint16(1), gotHandshake.Header.MessageSequence)
	_, ok = gotHandshake.Message.(*handshake.MessageClientHello)
	require.True(t, ok)
}

func TestPlaintextRecord13RejectsLegacyPlaintextContentTypes(t *testing.T) {
	record := &PlaintextRecord13{
		Header:  Header{Version: protocol.Version1_2},
		Content: &protocol.ChangeCipherSpec{},
	}

	_, err := record.Marshal()
	require.ErrorIs(t, err, dtlserrors.ErrInvalidContentType)

	header := Header{
		ContentType: protocol.ContentTypeApplicationData,
		Version:     protocol.Version1_2,
		ContentLen:  1,
	}
	raw, err := header.Marshal()
	require.NoError(t, err)
	raw = append(raw, 0xaa)

	var roundTrip PlaintextRecord13
	err = roundTrip.Unmarshal(raw)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidContentType)
}

func TestPlaintextRecord13RejectsOversizedContent(t *testing.T) {
	record := &PlaintextRecord13{
		Header:  Header{Version: protocol.Version1_2},
		Content: oversizedPlaintextContent13{},
	}

	_, err := record.Marshal()
	require.ErrorIs(t, err, ErrInvalidPacketLength)
}

func TestPlaintextRecord13RejectsOversizedUnmarshal(t *testing.T) {
	header := Header{
		ContentType: protocol.ContentTypeApplicationData,
		Version:     protocol.Version1_2,
		ContentLen:  maxDTLSPlaintextRecordLen + 1,
	}
	raw, err := header.Marshal()
	require.NoError(t, err)
	raw = append(raw, make([]byte, maxDTLSPlaintextRecordLen+1)...)

	var record PlaintextRecord13
	err = record.Unmarshal(raw)
	require.ErrorIs(t, err, ErrInvalidPacketLength)
}

func TestCiphertextRecord13RoundTrip(t *testing.T) {
	encryptedRecord := ciphertext13Payload(0xde)
	record := &CiphertextRecord13{
		Header: UnifiedHeader{
			EpochLow:       3,
			SequenceNumber: 0xaabb,
		},
		EncryptedRecord: encryptedRecord,
	}

	raw, err := record.Marshal()
	require.NoError(t, err)
	require.Equal(t, append([]byte{
		0x2f,
		0xaa, 0xbb,
		0x00, 0x10,
	}, encryptedRecord...), raw)

	var roundTrip CiphertextRecord13
	require.NoError(t, roundTrip.Unmarshal(raw))
	require.Equal(t, uint8(3), roundTrip.Header.EpochLow)
	require.Equal(t, uint16(0xaabb), roundTrip.Header.SequenceNumber)
	require.True(t, roundTrip.Header.SeqBit)
	require.Equal(t, uint16(16), roundTrip.Header.Length)
	require.True(t, roundTrip.Header.LengthBit)
	require.Equal(t, encryptedRecord, roundTrip.EncryptedRecord)
}

func TestCiphertextRecord13MarshalRefreshesLength(t *testing.T) {
	encryptedRecord := ciphertext13Payload(0xaa)
	record := &CiphertextRecord13{
		Header: UnifiedHeader{
			SequenceNumber: 0x01,
			Length:         4,
		},
		EncryptedRecord: encryptedRecord,
	}

	raw, err := record.Marshal()
	require.NoError(t, err)
	require.Equal(t, append([]byte{0x2c, 0x00, 0x01, 0x00, 0x10}, encryptedRecord...), raw)
	require.Equal(t, uint16(16), record.Header.Length)
	require.True(t, record.Header.SeqBit)
	require.True(t, record.Header.LengthBit)
}

func TestCiphertextRecord13MarshalRejectsShortEncryptedRecord(t *testing.T) {
	for recordLen := range minDTLSCiphertextRecordLen {
		record := &CiphertextRecord13{
			EncryptedRecord: make([]byte, recordLen),
		}

		_, err := record.Marshal()
		require.ErrorIs(t, err, ErrInvalidPacketLength, "record length %d", recordLen)
	}
}

func TestCiphertextRecord13RejectsOversizedEncryptedRecord(t *testing.T) {
	record := &CiphertextRecord13{
		EncryptedRecord: make([]byte, maxDTLSCiphertextRecordLen+1),
	}

	_, err := record.Marshal()
	require.ErrorIs(t, err, ErrInvalidPacketLength)
}

func TestCiphertextRecord13WithoutLengthUsesRemainder(t *testing.T) {
	encryptedRecord := ciphertext13Payload(0xaa)
	raw := append([]byte{0x21, 0x12}, encryptedRecord...)

	var roundTrip CiphertextRecord13
	require.NoError(t, roundTrip.Unmarshal(raw))
	require.Equal(t, uint8(1), roundTrip.Header.EpochLow)
	require.Equal(t, uint16(0x12), roundTrip.Header.SequenceNumber)
	require.False(t, roundTrip.Header.SeqBit)
	require.Equal(t, uint16(0), roundTrip.Header.Length)
	require.False(t, roundTrip.Header.LengthBit)
	require.Equal(t, encryptedRecord, roundTrip.EncryptedRecord)
}

func TestCiphertextRecord13RejectsLengthMismatch(t *testing.T) {
	var record CiphertextRecord13
	err := record.Unmarshal([]byte{0x2c, 0x00, 0x01, 0x00, 0x04, 0xaa, 0xbb})
	require.ErrorIs(t, err, ErrInvalidPacketLength)
}

func TestCiphertextRecord13UnmarshalRejectsShortEncryptedRecord(t *testing.T) {
	for recordLen := range minDTLSCiphertextRecordLen {
		var recordWithoutLength CiphertextRecord13
		rawWithoutLength := append([]byte{0x20, 0x01}, make([]byte, recordLen)...)
		err := recordWithoutLength.Unmarshal(rawWithoutLength)
		require.ErrorIs(t, err, ErrInvalidPacketLength, "record length %d without length bit", recordLen)

		var recordWithLength CiphertextRecord13
		rawWithLength := []byte{
			0x2c, 0x00, 0x01,
			byte(recordLen >> 8), byte(recordLen),
		}
		rawWithLength = append(rawWithLength, make([]byte, recordLen)...)
		err = recordWithLength.Unmarshal(rawWithLength)
		require.ErrorIs(t, err, ErrInvalidPacketLength, "record length %d with length bit", recordLen)
	}
}

func TestUnpackDatagram13Plaintext(t *testing.T) {
	plaintext := &PlaintextRecord13{
		Header:  Header{Version: protocol.Version1_2},
		Content: &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify},
	}
	plaintextRaw, err := plaintext.Marshal()
	require.NoError(t, err)

	records, err := UnpackDatagram13(plaintextRaw, 0, false)
	require.NoError(t, err)
	require.Equal(t, [][]byte{plaintextRaw}, records)
}

func TestUnpackDatagram13Ciphertext(t *testing.T) {
	encryptedRecord := ciphertext13Payload(0xaa)
	ciphertextWithLength := &CiphertextRecord13{
		Header: UnifiedHeader{
			SequenceNumber: 0x01,
		},
		EncryptedRecord: encryptedRecord,
	}
	ciphertextWithLengthRaw, err := ciphertextWithLength.Marshal()
	require.NoError(t, err)

	ciphertextWithoutLengthRaw := append([]byte{0x20, 0x02}, ciphertext13Payload(0xcc)...)

	datagram := append(append([]byte{}, ciphertextWithLengthRaw...), ciphertextWithoutLengthRaw...)
	records, err := UnpackDatagram13(datagram, 0, true)
	require.NoError(t, err)
	require.Equal(t, [][]byte{ciphertextWithLengthRaw, ciphertextWithoutLengthRaw}, records)
}

func TestUnpackDatagram13RejectsShortFinalCiphertextRecordWithoutLength(t *testing.T) {
	for recordLen := range minDTLSCiphertextRecordLen {
		raw := append([]byte{0x20, 0x01}, make([]byte, recordLen)...)

		_, err := UnpackDatagram13(raw, 0, true)
		require.ErrorIs(t, err, ErrInvalidPacketLength, "record length %d", recordLen)
	}
}

func TestUnpackDatagram13RejectsShortCiphertextRecordWithLength(t *testing.T) {
	for recordLen := range minDTLSCiphertextRecordLen {
		raw := []byte{
			0x2c, 0x00, 0x01,
			byte(recordLen >> 8), byte(recordLen),
		}
		raw = append(raw, make([]byte, recordLen)...)

		_, err := UnpackDatagram13(raw, 0, true)
		require.ErrorIs(t, err, ErrInvalidPacketLength, "record length %d", recordLen)
	}
}

func TestUnpackDatagram13MixedPlaintextAndCiphertext(t *testing.T) {
	plaintext := &PlaintextRecord13{
		Header:  Header{Version: protocol.Version1_2},
		Content: &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify},
	}
	plaintextRaw, err := plaintext.Marshal()
	require.NoError(t, err)

	ciphertext := &CiphertextRecord13{
		Header: UnifiedHeader{
			SequenceNumber: 0x01,
		},
		EncryptedRecord: ciphertext13Payload(0xaa),
	}
	ciphertextRaw, err := ciphertext.Marshal()
	require.NoError(t, err)

	datagram := append(append([]byte{}, plaintextRaw...), ciphertextRaw...)
	records, err := UnpackDatagram13(datagram, 0, true)
	require.NoError(t, err)
	require.Equal(t, [][]byte{plaintextRaw, ciphertextRaw}, records)
}

func TestUnpackDatagram13RejectsCiphertextMissingNegotiatedCID(t *testing.T) {
	ciphertext := &CiphertextRecord13{
		Header: UnifiedHeader{
			SequenceNumber: 0x01,
		},
		EncryptedRecord: ciphertext13Payload(0xaa),
	}
	raw, err := ciphertext.Marshal()
	require.NoError(t, err)

	_, err = UnpackDatagram13(raw, 4, true)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidCiphertextHeader)
}

func TestUnpackDatagram13RejectsCiphertextWithUnexpectedCID(t *testing.T) {
	ciphertext := &CiphertextRecord13{
		Header: UnifiedHeader{
			ConnectionID:   []byte{0x01, 0x02, 0x03, 0x04},
			SequenceNumber: 0x01,
		},
		EncryptedRecord: ciphertext13Payload(0xaa),
	}
	raw, err := ciphertext.Marshal()
	require.NoError(t, err)

	_, err = UnpackDatagram13(raw, 0, true)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidCiphertextHeader)
}

func TestUnpackDatagram13RejectsTruncatedCID(t *testing.T) {
	_, err := UnpackDatagram13([]byte{0x30, 0x01, 0x02}, 4, true)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidUnifiedHeaderFormat)
}

func TestUnpackDatagram13DiscardsRemainderOnMismatchedCID(t *testing.T) {
	first := &CiphertextRecord13{
		Header: UnifiedHeader{
			ConnectionID:   []byte{0x01, 0x02, 0x03, 0x04},
			SequenceNumber: 0x01,
		},
		EncryptedRecord: ciphertext13Payload(0xaa),
	}
	firstRaw, err := first.Marshal()
	require.NoError(t, err)

	second := &CiphertextRecord13{
		Header: UnifiedHeader{
			ConnectionID:   []byte{0x04, 0x03, 0x02, 0x01},
			SequenceNumber: 0x02,
		},
		EncryptedRecord: ciphertext13Payload(0xba),
	}
	secondRaw, err := second.Marshal()
	require.NoError(t, err)

	records, err := UnpackDatagram13(append(append([]byte{}, firstRaw...), secondRaw...), 4, true)
	require.NoError(t, err)
	require.Equal(t, [][]byte{firstRaw}, records)
}

func TestUnpackDatagram13RejectsLegacyPlaintextWhenCiphertextHeadersEnabled(t *testing.T) {
	header := Header{
		ContentType: protocol.ContentTypeApplicationData,
		Version:     protocol.Version1_2,
		ContentLen:  1,
	}
	raw, err := header.Marshal()
	require.NoError(t, err)
	raw = append(raw, 0xaa)

	_, err = UnpackDatagram13(raw, 0, true)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidContentType)
}

func TestRecordLayer13Interface(t *testing.T) {
	var plaintext RecordLayer13 = &PlaintextRecord13{}
	require.IsType(t, &Header{}, plaintext.RecordHeader())

	var ciphertext RecordLayer13 = &CiphertextRecord13{}
	require.IsType(t, &UnifiedHeader{}, ciphertext.RecordHeader())
}
