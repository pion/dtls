package dtls

import (
	"encoding/binary"
)

// https://tools.ietf.org/html/rfc5246#section-7.4
type handshakeType uint8

const (
	handshakeTypeHelloRequest       handshakeType = 0
	handshakeTypeClientHello        handshakeType = 1
	handshakeTypeServerHello        handshakeType = 2
	handshakeTypeCertificate        handshakeType = 11
	handshakeTypeServerKeyExchange  handshakeType = 12
	handshakeTypeCertificateRequest handshakeType = 13
	handshakeTypeServerHelloDone    handshakeType = 14
	handshakeTypeCertificateVerify  handshakeType = 15
	handshakeTypeClientKeyExchange  handshakeType = 16
	handshakeTypeFinished           handshakeType = 20

	// msg_len for Handshake messages assumes an extra 12 bytes for
	// sequence, fragment and version information
	handshakeMessageHeaderLength = 12
)

type handshakeMessage interface {
	marshal() ([]byte, error)
	unmarshal(data []byte) error

	handshakeType() handshakeType
}

// The handshake protocol is responsible for selecting a cipher spec and
// generating a master secret, which together comprise the primary
// cryptographic parameters associated with a secure session.  The
// handshake protocol can also optionally authenticate parties who have
// certificates signed by a trusted certificate authority.
// https://tools.ietf.org/html/rfc5246#section-7.3
type handshake struct {
	messageSequence  uint16
	fragmentOffset   uint32 // uint24 in spec
	fragmentLength   uint32 // uint24 in spec
	handshakeMessage handshakeMessage
}

func (h handshake) contentType() contentType {
	return contentTypeHandshake
}

func (h *handshake) marshal() ([]byte, error) {
	if h.handshakeMessage == nil {
		return nil, errHandshakeMessageUnset
	}

	messageBody, err := h.handshakeMessage.marshal()
	if err != nil {
		return nil, err
	}
	out := make([]byte, handshakeMessageHeaderLength)
	out[0] = byte(h.handshakeMessage.handshakeType())

	binary.BigEndian.PutUint16(out[4:], h.messageSequence)
	putBigEndianUint24(out[6:], h.fragmentOffset)

	out = append(out, messageBody...)

	// TODO currently ignoring fragment lengths, do not support fragmented messages
	h.fragmentLength = uint32(len(out) - handshakeMessageHeaderLength)
	putBigEndianUint24(out[1:], h.fragmentLength)
	putBigEndianUint24(out[9:], h.fragmentLength)

	return out, nil
}

func (h *handshake) unmarshal(data []byte) error {
	reportedLen := bigEndianUint24(data[1:])
	h.messageSequence = binary.BigEndian.Uint16(data[4:])
	h.fragmentOffset = bigEndianUint24(data[6:])
	h.fragmentLength = bigEndianUint24(data[9:])
	if uint32(len(data)-handshakeMessageHeaderLength) != reportedLen {
		return errLengthMismatch
	} else if reportedLen != h.fragmentLength {
		return errLengthMismatch
	}

	switch handshakeType(data[0]) {
	case handshakeTypeClientHello:
		h.handshakeMessage = &clientHello{}
	default:
		return errNotImplemented
	}
	return h.handshakeMessage.unmarshal(data[handshakeMessageHeaderLength:])
}
