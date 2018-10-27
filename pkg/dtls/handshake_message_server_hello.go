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
	version protocolVersion
	random  handshakeRandom

	cipherSuite       *cipherSuite
	compressionMethod *compressionMethod
	extensions        []extension
}

const handshakeMessageServerHelloVariableWidthStart = 2 + handshakeRandomLength

func (h handshakeMessageServerHello) handshakeType() handshakeType {
	return handshakeTypeServerHello
}

func (h *handshakeMessageServerHello) marshal() ([]byte, error) {
	return nil, errNotImplemented
}

func (h *handshakeMessageServerHello) unmarshal(data []byte) error {
	h.version.major = data[0]
	h.version.minor = data[1]

	if err := h.random.unmarshal(data[2 : 2+handshakeRandomLength]); err != nil {
		return err
	}

	currOffset := handshakeMessageServerHelloVariableWidthStart
	currOffset += int(data[currOffset]) + 1 // SessionID

	if cipherSuite, ok := cipherSuites[cipherSuiteID(binary.BigEndian.Uint16(data[currOffset:]))]; ok {
		h.cipherSuite = cipherSuite
		currOffset += 2
	} else {
		return errInvalidCipherSuite
	}

	if compressionMethod, ok := compressionMethods[compressionMethodID(data[currOffset])]; ok {
		h.compressionMethod = compressionMethod
		currOffset++
	} else {
		return errInvalidCompressionMethod
	}

	extensions, err := decodeExtensions(data[currOffset:])
	if err != nil {
		return err
	}
	h.extensions = extensions
	return nil
}
