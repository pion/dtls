// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"bytes"
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

const (
	maxDTLSPlaintextRecordLen  = 1 << 14
	minDTLSCiphertextRecordLen = 16
	maxDTLSCiphertextRecordLen = maxDTLSPlaintextRecordLen + 256
)

// HeaderLike is implemented by DTLS record header encodings.
type HeaderLike interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
	Size() int
}

// RecordLayer13 is implemented by DTLS 1.3 plaintext and ciphertext records.
type RecordLayer13 interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
	RecordHeader() HeaderLike
}

// PlaintextRecord13 implements DTLSPlaintext for epoch 0 records.
type PlaintextRecord13 struct {
	Header  Header
	Content protocol.Content
}

// Marshal encodes a DTLS 1.3 DTLSPlaintext record.
func (r *PlaintextRecord13) Marshal() ([]byte, error) {
	if r.Header.Epoch != 0 {
		return nil, errInvalidEpoch
	}
	if r.Header.Version == (protocol.Version{}) {
		r.Header.Version = protocol.Version1_2
	}

	contentType := r.Content.ContentType()
	if !isPlaintextRecord13ContentType(contentType) {
		return nil, errInvalidContentType
	}

	contentRaw, err := r.Content.Marshal()
	if err != nil {
		return nil, err
	}
	if !isPlaintextRecord13LegacyVersionForSend(r.Header.Version, contentType, contentRaw) {
		return nil, errUnsupportedProtocolVersion
	}
	if len(contentRaw) > maxDTLSPlaintextRecordLen {
		return nil, ErrInvalidPacketLength
	}

	r.Header.ContentLen = uint16(len(contentRaw)) //nolint:gosec // G115: checked above.
	r.Header.ContentType = r.Content.ContentType()

	headerRaw, err := r.Header.Marshal()
	if err != nil {
		return nil, err
	}

	return append(headerRaw, contentRaw...), nil
}

// Unmarshal populates a DTLS 1.3 DTLSPlaintext record from binary.
func (r *PlaintextRecord13) Unmarshal(data []byte) error {
	if err := unmarshalPlaintextRecord13Header(&r.Header, data); err != nil {
		return err
	}
	if r.Header.Epoch != 0 {
		return errInvalidEpoch
	}
	if r.Header.ContentLen > maxDTLSPlaintextRecordLen {
		return ErrInvalidPacketLength
	}

	contentStart := r.Header.Size()
	contentEnd := contentStart + int(r.Header.ContentLen)
	if len(data) != contentEnd {
		return ErrInvalidPacketLength
	}
	contentRaw := data[contentStart:contentEnd]

	switch r.Header.ContentType {
	case protocol.ContentTypeAlert:
		r.Content = &alert.Alert{}
	case protocol.ContentTypeHandshake:
		r.Content = &handshake.Handshake{}
	case protocol.ContentTypeACK:
		r.Content = &protocol.ACK{}
	default:
		return errInvalidContentType
	}

	return r.Content.Unmarshal(contentRaw)
}

// RecordHeader returns the record header.
func (r *PlaintextRecord13) RecordHeader() HeaderLike {
	return &r.Header
}

// CiphertextRecord13 implements DTLSCiphertext for protected records.
type CiphertextRecord13 struct {
	Header          UnifiedHeader
	EncryptedRecord []byte
}

// Marshal encodes a DTLS 1.3 DTLSCiphertext record.
func (r *CiphertextRecord13) Marshal() ([]byte, error) {
	if !isValidDTLSCiphertextRecordLen(len(r.EncryptedRecord)) {
		return nil, ErrInvalidPacketLength
	}
	r.Header.SeqBit = true
	r.Header.Length = uint16(len(r.EncryptedRecord)) //nolint:gosec // G115: checked above.
	r.Header.LengthBit = true

	headerRaw, err := r.Header.Marshal()
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(headerRaw)+len(r.EncryptedRecord))
	out = append(out, headerRaw...)
	out = append(out, r.EncryptedRecord...)

	return out, nil
}

// Unmarshal populates a DTLS 1.3 DTLSCiphertext record from binary.
func (r *CiphertextRecord13) Unmarshal(data []byte) error {
	if err := r.Header.Unmarshal(data); err != nil {
		return err
	}

	headerSize := unifiedHeaderWireSize(data[0], len(r.Header.ConnectionID))
	if len(data) < headerSize {
		return errBufferTooSmall
	}

	recordLen := len(data) - headerSize
	if r.Header.LengthBit {
		recordLen = int(r.Header.Length)
		if len(data)-headerSize != recordLen {
			return ErrInvalidPacketLength
		}
	}
	if recordLen > maxDTLSCiphertextRecordLen {
		return ErrInvalidPacketLength
	}
	if recordLen < minDTLSCiphertextRecordLen {
		return ErrInvalidPacketLength
	}

	r.EncryptedRecord = append([]byte{}, data[headerSize:headerSize+recordLen]...)

	return nil
}

// RecordHeader returns the record header.
func (r *CiphertextRecord13) RecordHeader() HeaderLike {
	return &r.Header
}

// UnpackDatagram13 extracts DTLS 1.3 records from a single datagram.
func UnpackDatagram13(buf []byte, cidLength int, ciphertextHeadersEnabled bool) ([][]byte, error) {
	out := [][]byte{}
	var firstCiphertextCID []byte

	for offset := 0; len(buf) != offset; {
		contentType := protocol.ContentType(buf[offset])
		if isPlaintextRecord13ContentType(contentType) {
			record, nextOffset, err := unpackPlaintextDatagram13Record(buf, offset)
			if err != nil {
				return nil, err
			}
			out = append(out, record)
			offset = nextOffset

			continue
		}

		if !ciphertextHeadersEnabled || !protocol.IsDTLS13Ciphertext(contentType) {
			return nil, errInvalidContentType
		}

		record, cid, nextOffset, done, err := unpackCiphertextDatagram13Record(buf, offset, cidLength)
		if err != nil {
			return nil, err
		}
		if isMismatchedCiphertextCID(&firstCiphertextCID, cid, cidLength) {
			return out, nil
		}
		out = append(out, record)
		if done {
			return out, nil
		}
		offset = nextOffset
	}

	return out, nil
}

func unpackPlaintextDatagram13Record(buf []byte, offset int) ([]byte, int, error) {
	if len(buf)-offset <= FixedHeaderSize {
		return nil, 0, ErrInvalidPacketLength
	}

	pktLen := FixedHeaderSize + int(binary.BigEndian.Uint16(buf[offset+fixedHeaderLenIdx:]))
	if offset+pktLen > len(buf) {
		return nil, 0, ErrInvalidPacketLength
	}

	return buf[offset : offset+pktLen], offset + pktLen, nil
}

func unpackCiphertextDatagram13Record(buf []byte, offset, cidLength int) ([]byte, []byte, int, bool, error) {
	header, err := unmarshalCiphertextDatagram13Header(buf[offset:], cidLength)
	if err != nil {
		return nil, nil, 0, false, err
	}

	headerSize := unifiedHeaderWireSize(buf[offset], len(header.ConnectionID))
	if !header.LengthBit {
		return unpackCiphertextDatagram13RecordWithoutLength(buf, offset, headerSize, header.ConnectionID)
	}

	return unpackCiphertextDatagram13RecordWithLength(buf, offset, headerSize, header)
}

func isMismatchedCiphertextCID(firstCID *[]byte, cid []byte, cidLength int) bool {
	if cidLength == 0 {
		return false
	}
	if *firstCID == nil {
		*firstCID = append([]byte{}, cid...)

		return false
	}

	return !bytes.Equal(*firstCID, cid)
}

func unmarshalCiphertextDatagram13Header(data []byte, cidLength int) (UnifiedHeader, error) {
	hasCID := data[0]&UnifiedHeaderCIDBit != 0
	if err := validateCiphertextCIDBit(hasCID, cidLength); err != nil {
		return UnifiedHeader{}, err
	}

	header := UnifiedHeader{}
	if hasCID {
		header.ConnectionID = make([]byte, cidLength)
	}

	return header, header.Unmarshal(data)
}

func validateCiphertextCIDBit(hasCID bool, cidLength int) error {
	switch {
	case cidLength > 0 && !hasCID:
		return errInvalidCiphertextHeader
	case cidLength == 0 && hasCID:
		return errInvalidCiphertextHeader
	default:
		return nil
	}
}

func unpackCiphertextDatagram13RecordWithoutLength(
	buf []byte,
	offset int,
	headerSize int,
	connectionID []byte,
) ([]byte, []byte, int, bool, error) {
	recordLen := len(buf) - offset - headerSize
	if !isValidDTLSCiphertextRecordLen(recordLen) {
		return nil, nil, 0, false, ErrInvalidPacketLength
	}

	return buf[offset:], connectionID, len(buf), true, nil
}

func unpackCiphertextDatagram13RecordWithLength(
	buf []byte,
	offset int,
	headerSize int,
	header UnifiedHeader,
) ([]byte, []byte, int, bool, error) {
	if !isValidDTLSCiphertextRecordLen(int(header.Length)) {
		return nil, nil, 0, false, ErrInvalidPacketLength
	}
	pktLen := headerSize + int(header.Length)
	if offset+pktLen > len(buf) {
		return nil, nil, 0, false, ErrInvalidPacketLength
	}

	return buf[offset : offset+pktLen], header.ConnectionID, offset + pktLen, false, nil
}

func isPlaintextRecord13ContentType(contentType protocol.ContentType) bool {
	return contentType == protocol.ContentTypeAlert ||
		contentType == protocol.ContentTypeHandshake ||
		contentType == protocol.ContentTypeACK
}

func unmarshalPlaintextRecord13Header(header *Header, data []byte) error {
	if len(data) < FixedHeaderSize {
		return errBufferTooSmall
	}

	// RFC 9147 requires receivers to ignore legacy_record_version, so do not
	// use Header.Unmarshal's protocol version validation for DTLS 1.3 plaintext.
	header.ContentType = protocol.ContentType(data[0])
	header.Version.Major = data[1]
	header.Version.Minor = data[2]
	header.Epoch = binary.BigEndian.Uint16(data[3:])
	header.SequenceNumber = uint64(data[5])<<40 |
		uint64(data[6])<<32 |
		uint64(data[7])<<24 |
		uint64(data[8])<<16 |
		uint64(data[9])<<8 |
		uint64(data[10])
	header.ConnectionID = nil
	header.ContentLen = binary.BigEndian.Uint16(data[fixedHeaderLenIdx:])

	return nil
}

func isValidDTLSCiphertextRecordLen(recordLen int) bool {
	return recordLen >= minDTLSCiphertextRecordLen &&
		recordLen <= maxDTLSCiphertextRecordLen
}

func isPlaintextRecord13LegacyVersionForSend(
	version protocol.Version,
	contentType protocol.ContentType,
	contentRaw []byte,
) bool {
	if version.Equal(protocol.Version1_2) {
		return true
	}
	if !version.Equal(protocol.Version1_0) {
		return false
	}

	// We do not support DTLS 1.0. DTLS 1.3 reuses this field as
	// legacy_record_version, and RFC 9147 allows {254,255} only for the initial
	// ClientHello for compatibility with old middleboxes.
	// We should add an e2e test for this.
	if contentType != protocol.ContentTypeHandshake {
		return false
	}

	var header handshake.Header
	if err := header.Unmarshal(contentRaw); err != nil {
		return false
	}

	return header.Type == handshake.TypeClientHello && header.MessageSequence == 0
}

func unifiedHeaderWireSize(firstByte byte, cidLength int) int {
	size := 1 + cidLength
	if firstByte&UnifiedHeaderSeqBit != 0 {
		size += 2
	} else {
		size++
	}
	if firstByte&UnifiedHeaderLengthBit != 0 {
		size += 2
	}

	return size
}
