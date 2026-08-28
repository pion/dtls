// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"encoding/binary"
	"math"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
)

// DTLS fixed size record layer header when Connection IDs are not in-use.

// ---------------------------------
// | Type   |   Version   |  Epoch |
// ---------------------------------
// | Epoch  |    Sequence Number   |
// ---------------------------------
// |   Sequence Number   |  Length |
// ---------------------------------
// | Length |      Fragment...     |
// ---------------------------------

const (
	// fixedHeaderLenIdx is the index at which the record layer content length is
	// specified in a fixed length header (i.e. one that does not include a
	// Connection ID).
	fixedHeaderLenIdx     = 11
	maxConnectionIDLength = 255

	maxDTLSPlaintextRecordLen  = 1 << 14
	minDTLSCiphertextRecordLen = 16
	maxDTLSCiphertextRecordLen = maxDTLSPlaintextRecordLen + 256
)

// RecordLayer describes a mutable outbound fixed-header DTLS record. Inbound
// datagrams are framed with UnpackDatagram and opened by connection state.
type RecordLayer struct {
	Header Header
}

// UnpackDatagramConfig configures datagram framing.
type UnpackDatagramConfig struct {
	// TargetVersion selects the permitted record forms. The zero value permits
	// both DTLS 1.2 and DTLS 1.3 forms for pre-negotiation stage.
	TargetVersion protocol.Version
	// CIDLength is the known receive CID length used to locate record fields.
	CIDLength int
	// CIDRequired requires the CID form for protected DTLS 1.2 records and at
	// least one CID-bearing record in each DTLS 1.3 datagram that contains a
	// unified record. Epoch-zero plaintext-only datagrams cannot carry a CID.
	CIDRequired bool

	noUnkeyedLiterals struct{}
}

type unpackedDatagramRecord struct {
	raw      []byte
	consumed int
	hasCID   bool
}

// MarshalRecord encodes one fixed-header or DTLS 1.2 CID record.
func MarshalRecord(header Header, contentType protocol.ContentType, content []byte) ([]byte, error) {
	if len(content) > math.MaxUint16 {
		return nil, ErrInvalidPacketLength
	}
	header.ContentLen = uint16(len(content)) //nolint:gosec // bounded above
	header.ContentType = contentType
	out := make([]byte, header.MarshalSize()+len(content))
	headerSize, err := header.MarshalTo(out)
	if err != nil {
		return nil, err
	}
	copy(out[headerSize:], content)

	return out, nil
}

// UnpackDatagram extracts all records from a single datagram.
// Note that as with TLS, multiple handshake messages may be placed in
// the same DTLS record, provided that there is room and that they are
// part of the same flight.  Thus, there are two acceptable ways to pack
// two DTLS messages into the same datagram: in the same record or in
// separate records.
// https://www.rfc-editor.org/rfc/rfc6347#section-4.2.3
// https://www.rfc-editor.org/rfc/rfc9147#section-4
//
// Callers must copy records retained after datagram is
// reused.
func UnpackDatagram(datagram []byte, config UnpackDatagramConfig) ([][]byte, error) {
	if err := validateUnpackDatagramConfig(config); err != nil {
		return nil, err
	}

	var records [][]byte
	cidPresent := false
	sawUnified := false
	for len(datagram) != 0 {
		currentIsUnified := protocol.IsDTLS13Ciphertext(protocol.ContentType(datagram[0]))
		record, err := unpackNextDatagramRecord(datagram, config)
		if err != nil {
			return unpackDatagramError(
				records,
				cidPresent,
				requiresDatagramCID(config, sawUnified || currentIsUnified),
				err,
			)
		}

		sawUnified = sawUnified || currentIsUnified
		cidPresent = cidPresent || record.hasCID
		records = append(records, record.raw)
		datagram = datagram[record.consumed:]
	}

	if requiresDatagramCID(config, sawUnified) && !cidPresent {
		return nil, dtlserrors.ErrInvalidCiphertextHeader
	}

	return records, nil
}

func requiresDatagramCID(config UnpackDatagramConfig, sawUnified bool) bool {
	return config.CIDRequired && sawUnified
}

func unpackNextDatagramRecord(
	datagram []byte,
	config UnpackDatagramConfig,
) (unpackedDatagramRecord, error) {
	contentType := protocol.ContentType(datagram[0])
	isUnified := protocol.IsDTLS13Ciphertext(contentType)
	if err := validateRecordForm(config.TargetVersion, contentType, isUnified); err != nil {
		return unpackedDatagramRecord{}, err
	}

	if isUnified {
		record, consumed, err := unpackUnifiedDatagramRecord(datagram, config.CIDLength)

		return unpackedDatagramRecord{
			raw:      record,
			consumed: consumed,
			hasCID:   datagram[0]&UnifiedHeaderCIDBit != 0,
		}, err
	}

	return unpackNextFixedDatagramRecord(datagram, contentType, config)
}

func unpackNextFixedDatagramRecord(
	datagram []byte,
	contentType protocol.ContentType,
	config UnpackDatagramConfig,
) (unpackedDatagramRecord, error) {
	headerSize := FixedHeaderSize
	hasCID := contentType == protocol.ContentTypeConnectionID
	if hasCID {
		if config.CIDLength == 0 {
			return unpackedDatagramRecord{}, ErrInvalidPacketLength
		}
		headerSize += config.CIDLength
	}

	record, consumed, err := unpackDatagramRecord(datagram, headerSize)
	if err != nil {
		return unpackedDatagramRecord{}, err
	}
	if err = validateFixedRecordPolicy(record, contentType, config); err != nil {
		return unpackedDatagramRecord{}, err
	}

	return unpackedDatagramRecord{raw: record, consumed: consumed, hasCID: hasCID}, nil
}

func validateFixedRecordPolicy(
	record []byte,
	contentType protocol.ContentType,
	config UnpackDatagramConfig,
) error {
	epoch := binary.BigEndian.Uint16(record[3:5])
	if config.TargetVersion.Equal(protocol.Version1_3) && epoch != 0 {
		return dtlserrors.ErrInvalidEpoch
	}
	if config.CIDRequired && epoch != 0 && contentType != protocol.ContentTypeConnectionID {
		return dtlserrors.ErrInvalidCiphertextHeader
	}

	return nil
}

func validateUnpackDatagramConfig(config UnpackDatagramConfig) error {
	_ = config.noUnkeyedLiterals

	if config.CIDLength < 0 || config.CIDLength > maxConnectionIDLength ||
		config.CIDRequired && config.CIDLength == 0 {
		return ErrInvalidPacketLength
	}

	if config.TargetVersion == (protocol.Version{}) ||
		config.TargetVersion.Equal(protocol.Version1_2) ||
		config.TargetVersion.Equal(protocol.Version1_3) {
		return nil
	}

	return dtlserrors.ErrUnsupportedProtocolVersion
}

func validateRecordForm(
	targetVersion protocol.Version,
	contentType protocol.ContentType,
	isUnified bool,
) error {
	switch {
	case targetVersion == (protocol.Version{}):
		return nil
	case targetVersion.Equal(protocol.Version1_2):
		if isUnified {
			return dtlserrors.ErrInvalidContentType
		}
	case targetVersion.Equal(protocol.Version1_3):
		if !isUnified && !isDTLS13PlaintextContentType(contentType) {
			return dtlserrors.ErrInvalidContentType
		}
	}

	return nil
}

func isDTLS13PlaintextContentType(contentType protocol.ContentType) bool {
	return contentType == protocol.ContentTypeAlert ||
		contentType == protocol.ContentTypeHandshake ||
		contentType == protocol.ContentTypeACK
}

func unpackDatagramError(
	records [][]byte,
	cidPresent bool,
	datagramCIDRequired bool,
	err error,
) ([][]byte, error) {
	if datagramCIDRequired && !cidPresent {
		return nil, err
	}

	return records, err
}

func unpackDatagramRecord(buf []byte, headerSize int) ([]byte, int, error) {
	if len(buf) <= headerSize {
		return nil, 0, ErrInvalidPacketLength
	}

	contentLength := int(binary.BigEndian.Uint16(buf[headerSize-2 : headerSize]))
	if contentLength > len(buf)-headerSize {
		return nil, 0, ErrInvalidPacketLength
	}

	consumed := headerSize + contentLength

	return buf[:consumed], consumed, nil
}

// CiphertextRecord implements DTLSCiphertext for protected records.
type CiphertextRecord struct {
	Header          UnifiedHeader
	EncryptedRecord []byte
}

// Marshal encodes a DTLS 1.3 DTLSCiphertext record.
func (r *CiphertextRecord) Marshal() ([]byte, error) {
	if err := r.prepareMarshal(); err != nil {
		return nil, err
	}

	out := make([]byte, r.MarshalSize())
	_, err := r.marshalTo(out)

	return out, err
}

// MarshalSize returns the minimal buffer size required for MarshalTo.
func (r *CiphertextRecord) MarshalSize() int {
	return 1 + len(r.Header.ConnectionID) + 2 + 2 + len(r.EncryptedRecord)
}

// MarshalTo encodes a DTLS 1.3 DTLSCiphertext record to a pre-allocated buffer.
func (r *CiphertextRecord) MarshalTo(out []byte) (int, error) {
	if err := r.prepareMarshal(); err != nil {
		return 0, err
	}

	return r.marshalTo(out)
}

func (r *CiphertextRecord) prepareMarshal() error {
	if !isValidDTLSCiphertextRecordLen(len(r.EncryptedRecord)) {
		return ErrInvalidPacketLength
	}
	if len(r.Header.ConnectionID) > math.MaxUint8 {
		return dtlserrors.ErrCIDTooBig
	}

	r.Header.SeqBit = true
	r.Header.Length = uint16(len(r.EncryptedRecord)) //nolint:gosec // G115: checked above.
	r.Header.LengthBit = true

	return nil
}

func (r *CiphertextRecord) marshalTo(out []byte) (int, error) {
	if len(out) < r.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	headerSize, err := r.Header.MarshalTo(out)
	if err != nil {
		return 0, err
	}
	copy(out[headerSize:], r.EncryptedRecord)

	return headerSize + len(r.EncryptedRecord), nil
}

func unpackUnifiedDatagramRecord(buf []byte, cidLength int) ([]byte, int, error) {
	firstByte := buf[0]
	headerCIDLength := 0
	if firstByte&UnifiedHeaderCIDBit != 0 {
		if cidLength == 0 {
			return nil, 0, ErrInvalidPacketLength
		}
		headerCIDLength = cidLength
	}

	headerSize := unifiedHeaderWireSize(firstByte, headerCIDLength)
	if len(buf) < headerSize {
		return nil, 0, ErrInvalidPacketLength
	}

	if firstByte&UnifiedHeaderLengthBit == 0 {
		recordLen := len(buf) - headerSize
		if !isValidDTLSCiphertextRecordLen(recordLen) {
			return nil, 0, ErrInvalidPacketLength
		}

		return buf, len(buf), nil
	}

	recordLen := int(binary.BigEndian.Uint16(buf[headerSize-2 : headerSize]))
	if !isValidDTLSCiphertextRecordLen(recordLen) || recordLen > len(buf)-headerSize {
		return nil, 0, ErrInvalidPacketLength
	}
	consumed := headerSize + recordLen

	return buf[:consumed], consumed, nil
}

func isValidDTLSCiphertextRecordLen(recordLen int) bool {
	return recordLen >= minDTLSCiphertextRecordLen &&
		recordLen <= maxDTLSCiphertextRecordLen
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
