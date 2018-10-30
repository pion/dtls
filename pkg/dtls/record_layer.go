package dtls

import (
	"encoding/binary"
)

const (
	recordLayerSize   = 13
	maxSequenceNumber = 0x0000FFFFFFFFFFFF

	dtls1_2Major = 0xfe
	dtls1_2Minor = 0xfd
)

var protocolVersion1_2 = protocolVersion{dtls1_2Major, dtls1_2Minor}

// https://tools.ietf.org/html/rfc4346#section-6.2.1
type protocolVersion struct {
	major, minor uint8
}

/*
 The TLS Record Layer which handles all data transport.
 The record layer is assumed to sit directly on top of some
 reliable transport such as TCP. The record layer can carry four types of content:

 1. Handshake messages—used for algorithm negotiation and key establishment.
 2. ChangeCipherSpec messages—really part of the handshake but technically a separate kind of message.
 3. Alert messages—used to signal that errors have occurred
 4. Application layer data

 The DTLS record layer is extremely similar to that of TLS 1.1.  The
 only change is the inclusion of an explicit sequence number in the
 record.  This sequence number allows the recipient to correctly
 verify the TLS MAC.
 https://tools.ietf.org/html/rfc4347#section-4.1
*/
type recordLayer struct {
	protocolVersion protocolVersion
	epoch           uint16
	sequenceNumber  uint64 // uint48 in spec
	content         content
}

func (r *recordLayer) marshal() ([]byte, error) {
	contentRaw, err := r.content.marshal()
	if err != nil {
		return nil, err
	} else if r.sequenceNumber > maxSequenceNumber {
		return nil, errSequenceNumberOverflow
	}

	out := make([]byte, recordLayerSize)
	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(out[3:], r.sequenceNumber)
	out[0] = byte(r.content.contentType())
	out[1] = r.protocolVersion.major
	out[2] = r.protocolVersion.minor
	binary.BigEndian.PutUint16(out[3:], r.epoch)
	binary.BigEndian.PutUint16(out[recordLayerSize-2:], uint16(len(contentRaw)))

	return append(out, contentRaw...), nil
}

func (r *recordLayer) unmarshal(data []byte) error {
	r.protocolVersion.major = data[1]
	r.protocolVersion.minor = data[2]
	r.epoch = binary.BigEndian.Uint16(data[3:])

	// SequenceNumber is stored as uint48, make into uint64
	seqCopy := make([]byte, 8)
	copy(seqCopy[2:], data[5:11])
	r.sequenceNumber = binary.BigEndian.Uint64(seqCopy)

	switch contentType(data[0]) {
	case contentTypeChangeCipherSpec:
		r.content = &changeCipherSpec{}
	case contentTypeAlert:
		r.content = &alert{}
	case contentTypeHandshake:
		r.content = &handshake{}
	case contentTypeApplicationData:
		r.content = &applicationData{}
	default:
		return errInvalidContentType
	}

	return r.content.unmarshal(data[recordLayerSize:])
}

// Note that as with TLS, multiple handshake messages may be placed in
// the same DTLS record, provided that there is room and that they are
// part of the same flight.  Thus, there are two acceptable ways to pack
// two DTLS messages into the same datagram: in the same record or in
// separate records.
// https://tools.ietf.org/html/rfc6347#section-4.2.3
func unpackDatagram(buf []byte) ([][]byte, error) {
	out := [][]byte{}

	for offset := 0; len(buf) != offset; {
		if len(buf)-offset <= recordLayerSize {
			return nil, errDTLSPacketInvalidLength
		}

		pktLen := (recordLayerSize + int(binary.BigEndian.Uint16(buf[offset+11:])))
		out = append(out, buf[offset:offset+pktLen])
		offset += pktLen
	}

	return out, nil
}
