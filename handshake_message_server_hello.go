package dtls

import (
	"encoding/binary"
)

/*
The server will send this message in response to a ClientHello
message when it was able to find an acceptable set of algorithms.
If it cannot find such a match, it will respond with a handshake
failure alert.
https://tools.ietf.org/html/rfc5246#section-7.4.1.3
*/
type handshakeMessageServerHello struct {
	version ProtocolVersion
	random  handshakeRandom

	cipherSuiteID     CipherSuiteID
	compressionMethod *compressionMethod
	extensions        []extension
}

const handshakeMessageServerHelloVariableWidthStart = 2 + handshakeRandomLength

func (h handshakeMessageServerHello) handshakeType() handshakeType {
	return handshakeTypeServerHello
}

func (h *handshakeMessageServerHello) Marshal() ([]byte, error) {
	if h.cipherSuiteID == 0 {
		return nil, errCipherSuiteUnset
	} else if h.compressionMethod == nil {
		return nil, errCompressionMethodUnset
	}

	out := make([]byte, handshakeMessageServerHelloVariableWidthStart)
	out[0] = h.version.Major
	out[1] = h.version.Minor

	rand := h.random.marshalFixed()
	copy(out[2:], rand[:])

	out = append(out, 0x00) // SessionID

	out = append(out, []byte{0x00, 0x00}...)
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(h.cipherSuiteID))

	out = append(out, byte(h.compressionMethod.id))

	extensions, err := encodeExtensions(h.extensions)
	if err != nil {
		return nil, err
	}

	return append(out, extensions...), nil
}

func (h *handshakeMessageServerHello) Unmarshal(data []byte) error {
	if len(data) < 2+handshakeRandomLength {
		return errBufferTooSmall
	}

	h.version.Major = data[0]
	h.version.Minor = data[1]

	var random [handshakeRandomLength]byte
	copy(random[:], data[2:])
	h.random.unmarshalFixed(random)

	currOffset := handshakeMessageServerHelloVariableWidthStart
	currOffset += int(data[currOffset]) + 1 // SessionID
	if len(data) < (currOffset + 2) {
		return errBufferTooSmall
	}
	cipherSuiteID := CipherSuiteID(binary.BigEndian.Uint16(data[currOffset:]))
	if cipherSuiteID == 0 {
		return errInvalidCipherSuite
	}
	h.cipherSuiteID = cipherSuiteID
	currOffset += 2
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	if compressionMethod, ok := compressionMethods()[compressionMethodID(data[currOffset])]; ok {
		h.compressionMethod = compressionMethod
		currOffset++
	} else {
		return errInvalidCompressionMethod
	}

	if len(data) <= currOffset {
		h.extensions = []extension{}
		return nil
	}

	extensions, err := decodeExtensions(data[currOffset:])
	if err != nil {
		return err
	}
	h.extensions = extensions
	return nil
}
