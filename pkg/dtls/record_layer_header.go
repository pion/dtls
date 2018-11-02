package dtls

import "encoding/binary"

type recordLayerHeader struct {
	contentType     contentType
	contentLen      uint16
	protocolVersion protocolVersion
	epoch           uint16
	sequenceNumber  uint64 // uint48 in spec

}

const (
	recordLayerHeaderSize = 13
	maxSequenceNumber     = 0x0000FFFFFFFFFFFF

	dtls1_2Major = 0xfe
	dtls1_2Minor = 0xfd
)

var protocolVersion1_2 = protocolVersion{dtls1_2Major, dtls1_2Minor}

// https://tools.ietf.org/html/rfc4346#section-6.2.1
type protocolVersion struct {
	major, minor uint8
}

func (r *recordLayerHeader) marshal() ([]byte, error) {
	if r.sequenceNumber > maxSequenceNumber {
		return nil, errSequenceNumberOverflow
	}

	out := make([]byte, recordLayerHeaderSize)
	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(out[3:], r.sequenceNumber)
	out[0] = byte(r.contentType)
	out[1] = r.protocolVersion.major
	out[2] = r.protocolVersion.minor
	binary.BigEndian.PutUint16(out[3:], r.epoch)
	binary.BigEndian.PutUint16(out[recordLayerHeaderSize-2:], r.contentLen)
	return out, nil
}

func (r *recordLayerHeader) unmarshal(data []byte) error {
	r.contentType = contentType(data[0])
	r.protocolVersion.major = data[1]
	r.protocolVersion.minor = data[2]
	r.epoch = binary.BigEndian.Uint16(data[3:])

	// SequenceNumber is stored as uint48, make into uint64
	seqCopy := make([]byte, 8)
	copy(seqCopy[2:], data[5:11])
	r.sequenceNumber = binary.BigEndian.Uint64(seqCopy)

	return nil
}
