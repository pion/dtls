// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package recordlayer frames, inspects, and encodes DTLS wire records.
package recordlayer

import (
	"encoding/binary"
	"math"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/recordwire"
	"github.com/pion/dtls/v4/internal/util"
	"github.com/pion/dtls/v4/pkg/protocol"
)

const (
	// FixedHeaderSize is the fixed record header size without a CID.
	FixedHeaderSize = recordwire.FixedHeaderSize
	// MaxSequenceNumber is the largest sequence number in a fixed record header.
	MaxSequenceNumber = recordwire.MaxSequenceNumber

	maxConnectionIDLength      = math.MaxUint8
	minDTLSCiphertextRecordLen = 16
	maxDTLSCiphertextRecordLen = (1 << 14) + 256
)

// RecordConfig selects fixed-header fields. Version is the wire version.
// ConnectionID must be nonempty exactly when ContentType is ContentTypeConnectionID.
type RecordConfig struct {
	ContentType    protocol.ContentType
	Version        protocol.Version
	Epoch          uint16
	SequenceNumber uint64
	ConnectionID   []byte
}

// CiphertextConfig selects unified record wire fields. SequenceNumber is the
// wire value (masked for protected traffic).
// A record without LengthPresent must be last in its datagram.
type CiphertextConfig struct {
	EpochLow        uint8
	SequenceNumber  uint16
	TwoByteSequence bool
	ConnectionID    []byte
	LengthPresent   bool
}

// MarshalRecord encodes one fixed-header record, deriving its payload length.
func MarshalRecord(config RecordConfig, payload []byte) ([]byte, error) {
	if len(payload) > math.MaxUint16 {
		return nil, ErrInvalidPacketLength
	}
	if len(config.ConnectionID) > maxConnectionIDLength {
		return nil, dtlserrors.ErrCIDTooBig
	}
	if config.SequenceNumber > MaxSequenceNumber {
		return nil, dtlserrors.ErrSequenceNumberOverflow
	}
	if config.ContentType == 0 || protocol.IsDTLS13Ciphertext(config.ContentType) ||
		(config.ContentType == protocol.ContentTypeConnectionID) != (len(config.ConnectionID) != 0) {
		return nil, dtlserrors.ErrInvalidContentType
	}
	if config.Version != protocol.Version1_0 && config.Version != protocol.Version1_2 {
		return nil, dtlserrors.ErrUnsupportedProtocolVersion
	}
	headerLen := FixedHeaderSize + len(config.ConnectionID)
	out := make([]byte, headerLen+len(payload))
	out[0], out[1], out[2] = byte(config.ContentType), config.Version.Major(), config.Version.Minor()
	binary.BigEndian.PutUint16(out[3:], config.Epoch)
	util.PutBigEndianUint48(out[5:], config.SequenceNumber)
	copy(out[11:], config.ConnectionID)
	binary.BigEndian.PutUint16(out[headerLen-2:], uint16(len(payload))) //nolint:gosec // Checked above.
	copy(out[headerLen:], payload)

	return out, nil
}

// MarshalCiphertext encodes one unified record with the selected C/S/L layout.
// It derives the length.
func MarshalCiphertext(config CiphertextConfig, ciphertext []byte) ([]byte, error) {
	if !isValidDTLSCiphertextRecordLen(len(ciphertext)) {
		return nil, ErrInvalidPacketLength
	}
	if len(config.ConnectionID) > maxConnectionIDLength {
		return nil, dtlserrors.ErrCIDTooBig
	}
	out := make([]byte, 0, 5+len(config.ConnectionID)+len(ciphertext))
	out, err := recordwire.AppendUnifiedHeader(out, config.EpochLow, config.SequenceNumber, config.TwoByteSequence, config.ConnectionID, config.LengthPresent, len(ciphertext))
	if err != nil {
		return nil, err
	}

	return append(out, ciphertext...), nil
}

// ParsedRecord borrows its input. Keep it unchanged while using returned slices.
type ParsedRecord struct {
	raw       []byte
	headerLen int
	cidLen    int
}

// ParseRecord parses exactly one fixed or unified record with an explicit CID
// length.
func ParseRecord(raw []byte, cidLength int) (ParsedRecord, error) {
	headerLen, payloadLen, err := recordwire.DecodeHeader(raw, cidLength)
	if err != nil {
		return ParsedRecord{}, err
	}
	record := ParsedRecord{raw: raw, headerLen: headerLen}
	if payloadLen != len(raw)-headerLen {
		return ParsedRecord{}, ErrInvalidPacketLength
	}
	if record.IsUnified() {
		if !isValidDTLSCiphertextRecordLen(payloadLen) {
			return ParsedRecord{}, ErrInvalidPacketLength
		}
		if raw[0]&recordwire.CIDBit != 0 {
			record.cidLen = cidLength
		}
	} else {
		version := protocol.VersionFromBytes(raw[1], raw[2])
		if version != protocol.Version1_0 && version != protocol.Version1_2 {
			return ParsedRecord{}, dtlserrors.ErrUnsupportedProtocolVersion
		}
		record.cidLen = headerLen - FixedHeaderSize
	}

	return record, nil
}

// IsUnified reports whether this is a DTLS 1.3 unified header.
func (r ParsedRecord) IsUnified() bool {
	return len(r.raw) != 0 && protocol.IsDTLS13Ciphertext(protocol.ContentType(r.raw[0]))
}

// Raw returns the exact borrowed wire record.
func (r ParsedRecord) Raw() []byte { return r.raw }

// HeaderBytes returns the exact borrowed header, including masked sequence bytes.
func (r ParsedRecord) HeaderBytes() []byte { return r.raw[:r.headerLen] }

// Payload returns the borrowed fragment or ciphertext.
func (r ParsedRecord) Payload() []byte { return r.raw[r.headerLen:] }

// ConnectionID returns the borrowed CID, or nil when absent.
func (r ParsedRecord) ConnectionID() []byte {
	if r.cidLen == 0 {
		return nil
	}

	offset := 11
	if r.IsUnified() {
		offset = 1
	}

	return r.raw[offset : offset+r.cidLen]
}

// ContentType returns the fixed header's outer type, or zero for unified records.
func (r ParsedRecord) ContentType() protocol.ContentType {
	if r.IsUnified() || len(r.raw) == 0 {
		return 0
	}

	return protocol.ContentType(r.raw[0])
}

// Version returns the fixed header's wire version, or zero for unified records.
func (r ParsedRecord) Version() protocol.Version {
	if r.IsUnified() || len(r.raw) == 0 {
		return 0
	}

	return protocol.VersionFromBytes(r.raw[1], r.raw[2])
}

// Epoch returns the fixed header's epoch, or zero for unified records.
func (r ParsedRecord) Epoch() uint16 {
	if r.IsUnified() || len(r.raw) == 0 {
		return 0
	}

	return binary.BigEndian.Uint16(r.raw[3:])
}

// EpochLow returns the two epoch bits of a unified header, or zero otherwise.
func (r ParsedRecord) EpochLow() uint8 {
	if !r.IsUnified() {
		return 0
	}

	return r.raw[0] & recordwire.EpochMask
}

// SequenceNumber returns the fixed sequence or masked truncated unified sequence.
func (r ParsedRecord) SequenceNumber() uint64 {
	if len(r.raw) == 0 {
		return 0
	}
	offset := 5
	if r.IsUnified() {
		offset = 1 + r.cidLen
	}
	var sequence uint64
	for _, b := range r.raw[offset : offset+r.SequenceBytes()] {
		sequence = sequence<<8 | uint64(b)
	}

	return sequence
}

// SequenceBytes returns the wire sequence width (6, 2, or 1), or 0 when empty.
func (r ParsedRecord) SequenceBytes() int {
	if len(r.raw) == 0 {
		return 0
	}
	if !r.IsUnified() {
		return 6
	}
	if r.raw[0]&recordwire.SequenceBit != 0 {
		return 2
	}

	return 1
}

// LengthPresent reports whether the wire header carries an explicit length.
func (r ParsedRecord) LengthPresent() bool {
	return len(r.raw) != 0 && (!r.IsUnified() || r.raw[0]&recordwire.LengthBit != 0)
}

// UnpackDatagramConfig configures datagram framing.
type UnpackDatagramConfig struct {
	// TargetVersion selects record forms; zero permits both DTLS 1.2 and 1.3.
	TargetVersion protocol.Version
	// CIDLength is the known receive CID length used to locate record fields.
	CIDLength int
	// CIDRequired requires CID on each protected DTLS 1.2 record, or at least
	// once per DTLS 1.3 datagram containing unified records.
	CIDRequired bool

	noUnkeyedLiterals struct{}
}

// UnpackDatagram returns borrowed records from a datagram.
//
//nolint:cyclop
func UnpackDatagram(datagram []byte, config UnpackDatagramConfig) (records [][]byte, err error) {
	if err = validateUnpackDatagramConfig(config); err != nil {
		return nil, err
	}

	cidPresent, sawUnified := false, false
	for len(datagram) != 0 {
		unified := protocol.IsDTLS13Ciphertext(protocol.ContentType(datagram[0]))
		sawUnified = sawUnified || unified
		var record []byte
		record, err = nextRecord(datagram, config)
		if err != nil {
			break
		}
		cidPresent = cidPresent || (unified && record[0]&recordwire.CIDBit != 0) || record[0] == byte(protocol.ContentTypeConnectionID)
		records = append(records, record)
		datagram = datagram[len(record):]
	}
	if config.CIDRequired && sawUnified && !cidPresent {
		records = nil
		if err == nil {
			err = dtlserrors.ErrInvalidCiphertextHeader
		}
	}

	return records, err
}

//nolint:cyclop
func nextRecord(datagram []byte, config UnpackDatagramConfig) ([]byte, error) {
	contentType := protocol.ContentType(datagram[0])
	unified := protocol.IsDTLS13Ciphertext(contentType)
	if config.TargetVersion == protocol.Version1_2 && unified ||
		config.TargetVersion == protocol.Version1_3 && !unified && !isDTLS13PlaintextContentType(contentType) {
		return nil, dtlserrors.ErrInvalidContentType
	}
	headerLen, payloadLen, err := recordwire.DecodeHeader(datagram, config.CIDLength)
	if err != nil {
		return nil, err
	}
	if payloadLen > len(datagram)-headerLen || unified && !isValidDTLSCiphertextRecordLen(payloadLen) || !unified && len(datagram) <= headerLen {
		return nil, ErrInvalidPacketLength
	}
	if !unified {
		epoch := binary.BigEndian.Uint16(datagram[3:5])
		if config.TargetVersion == protocol.Version1_3 && epoch != 0 {
			return nil, dtlserrors.ErrInvalidEpoch
		}
		if config.CIDRequired && epoch != 0 && contentType != protocol.ContentTypeConnectionID {
			return nil, dtlserrors.ErrInvalidCiphertextHeader
		}
	}

	return datagram[:headerLen+payloadLen], nil
}

func validateUnpackDatagramConfig(config UnpackDatagramConfig) error {
	_ = config.noUnkeyedLiterals

	if config.CIDLength < 0 || config.CIDLength > maxConnectionIDLength ||
		config.CIDRequired && config.CIDLength == 0 {
		return ErrInvalidPacketLength
	}

	if config.TargetVersion == 0 || config.TargetVersion == protocol.Version1_2 || config.TargetVersion == protocol.Version1_3 {
		return nil
	}

	return dtlserrors.ErrUnsupportedProtocolVersion
}

func isDTLS13PlaintextContentType(contentType protocol.ContentType) bool {
	return contentType == protocol.ContentTypeAlert || contentType == protocol.ContentTypeHandshake || contentType == protocol.ContentTypeACK
}

func isValidDTLSCiphertextRecordLen(recordLen int) bool {
	return recordLen >= minDTLSCiphertextRecordLen && recordLen <= maxDTLSCiphertextRecordLen
}
