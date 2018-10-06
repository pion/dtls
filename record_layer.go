package main

import (
	"encoding/binary"
)

const (
	recordLayerSize = 13
)

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
	return nil, nil
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
	if err := r.content.unmarshal(data[recordLayerSize:]); err != nil {
		return err
	}

	return nil
}

// decodeUDPPacket proccesses a UDP packet which may contain multiple DTLS packets
func decodeUDPPacket(buf []byte) ([]*recordLayer, error) {
	out := []*recordLayer{}

	for offset := 0; len(buf) != offset; {
		if len(buf)-offset <= recordLayerSize {
			return nil, errDTLSPacketInvalidLength
		}

		pktLen := (recordLayerSize + int(binary.BigEndian.Uint16(buf[11:])))
		r := &recordLayer{}
		if err := r.unmarshal(buf[offset : offset+pktLen]); err != nil {
			return nil, err
		}

		out = append(out, r)
		offset += pktLen
	}

	return out, nil
}
