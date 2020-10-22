package dtls

import "encoding/binary"

type RecordLayerHeader struct {
	ContentType     ContentType
	ContentLen      uint16
	ProtocolVersion ProtocolVersion
	Epoch           uint16
	SequenceNumber  uint64 // uint48 in spec
}

const (
	recordLayerHeaderSize = 13
	maxSequenceNumber     = 0x0000FFFFFFFFFFFF

	dtls1_2Major = 0xfe
	dtls1_2Minor = 0xfd

	dtls1_0Major = 0xfe
	dtls1_0Minor = 0xff

	// VersionDTLS12 is the DTLS version in the same style as
	// VersionTLSXX from crypto/tls
	VersionDTLS12 = 0xfefd
)

var (
	ProtocolVersion1_0 = ProtocolVersion{dtls1_0Major, dtls1_0Minor} //nolint:gochecknoglobals
	ProtocolVersion1_2 = ProtocolVersion{dtls1_2Major, dtls1_2Minor} //nolint:gochecknoglobals
)

// https://tools.ietf.org/html/rfc4346#section-6.2.1
type ProtocolVersion struct {
	Major, Minor uint8
}

func (v ProtocolVersion) Equal(x ProtocolVersion) bool {
	return v.Major == x.Major && v.Minor == x.Minor
}

func (r *RecordLayerHeader) Marshal() ([]byte, error) {
	if r.SequenceNumber > maxSequenceNumber {
		return nil, errSequenceNumberOverflow
	}

	out := make([]byte, recordLayerHeaderSize)
	out[0] = byte(r.ContentType)
	out[1] = r.ProtocolVersion.Major
	out[2] = r.ProtocolVersion.Minor
	binary.BigEndian.PutUint16(out[3:], r.Epoch)
	putBigEndianUint48(out[5:], r.SequenceNumber)
	binary.BigEndian.PutUint16(out[recordLayerHeaderSize-2:], r.ContentLen)
	return out, nil
}

func (r *RecordLayerHeader) Unmarshal(data []byte) error {
	if len(data) < recordLayerHeaderSize {
		return errBufferTooSmall
	}
	r.ContentType = ContentType(data[0])
	r.ProtocolVersion.Major = data[1]
	r.ProtocolVersion.Minor = data[2]
	r.Epoch = binary.BigEndian.Uint16(data[3:])

	// SequenceNumber is stored as uint48, make into uint64
	seqCopy := make([]byte, 8)
	copy(seqCopy[2:], data[5:11])
	r.SequenceNumber = binary.BigEndian.Uint64(seqCopy)

	if !r.ProtocolVersion.Equal(ProtocolVersion1_0) && !r.ProtocolVersion.Equal(ProtocolVersion1_2) {
		return errUnsupportedProtocolVersion
	}

	return nil
}
