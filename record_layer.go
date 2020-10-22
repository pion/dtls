package dtls

import (
	"encoding/binary"
)

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
type RecordLayer struct {
	RecordLayerHeader RecordLayerHeader
	Content           Content
}

func (r *RecordLayer) Marshal() ([]byte, error) {
	contentRaw, err := r.Content.Marshal()
	if err != nil {
		return nil, err
	}

	r.RecordLayerHeader.ContentLen = uint16(len(contentRaw))
	r.RecordLayerHeader.ContentType = r.Content.ContentType()

	headerRaw, err := r.RecordLayerHeader.Marshal()
	if err != nil {
		return nil, err
	}

	return append(headerRaw, contentRaw...), nil
}

func (r *RecordLayer) Unmarshal(data []byte) error {
	if len(data) < recordLayerHeaderSize {
		return errBufferTooSmall
	}
	if err := r.RecordLayerHeader.Unmarshal(data); err != nil {
		return err
	}

	switch ContentType(data[0]) {
	case ContentTypeChangeCipherSpec:
		r.Content = &changeCipherSpec{}
	case ContentTypeAlert:
		r.Content = &alert{}
	case ContentTypeHandshake:
		r.Content = &handshake{}
	case ContentTypeApplicationData:
		r.Content = &applicationData{}
	default:
		return errInvalidContentType
	}

	return r.Content.Unmarshal(data[recordLayerHeaderSize:])
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
		if len(buf)-offset <= recordLayerHeaderSize {
			return nil, errInvalidPacketLength
		}

		pktLen := (recordLayerHeaderSize + int(binary.BigEndian.Uint16(buf[offset+11:])))
		if offset+pktLen > len(buf) {
			return nil, errInvalidPacketLength
		}

		out = append(out, buf[offset:offset+pktLen])
		offset += pktLen
	}

	return out, nil
}
