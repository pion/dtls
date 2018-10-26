package dtls

import (
	"encoding/binary"
)

/*
When a client first connects to a server it is required to send
the client hello as its first message.  The client can also send a
client hello in response to a hello request or on its own
initiative in order to renegotiate the security parameters in an
existing connection.
*/
type handshakeMessageClientHello struct {
	version protocolVersion
	random  handshakeRandom
	cookie  []byte

	cipherSuites       []*cipherSuite
	compressionMethods []*compressionMethod
	extensions         []extension
}

const handshakeMessageClientHelloVariableWidthStart = 34

func (c handshakeMessageClientHello) handshakeType() handshakeType {
	return handshakeTypeClientHello
}

func (c *handshakeMessageClientHello) marshal() ([]byte, error) {
	if len(c.cookie) > 255 {
		return nil, errCookieTooLong
	}

	out := make([]byte, handshakeMessageClientHelloVariableWidthStart)
	out[0] = c.version.major
	out[1] = c.version.minor

	rand, err := c.random.marshal()
	if err != nil {
		return nil, err
	}
	copy(out[2:], rand)

	out = append(out, 0x00) // SessionID

	out = append(out, byte(len(c.cookie)))
	out = append(out, c.cookie...)
	out = append(out, encodeCipherSuites(c.cipherSuites)...)
	out = append(out, encodeCompressionMethods(c.compressionMethods)...)

	extensions, err := encodeExtensions(c.extensions)
	if err != nil {
		return nil, err
	}

	return append(out, extensions...), nil
}

func (c *handshakeMessageClientHello) unmarshal(data []byte) error {
	c.version.major = data[0]
	c.version.minor = data[1]

	if err := c.random.unmarshal(data[2 : 2+handshakeRandomLength]); err != nil {
		return err
	}

	// rest of packet has variable width sections
	currOffset := handshakeMessageClientHelloVariableWidthStart
	currOffset += int(data[currOffset]) + 1 // SessionID

	currOffset++
	c.cookie = append([]byte{}, data[currOffset:currOffset+int(data[currOffset-1])]...)
	currOffset += len(c.cookie)

	// Cipher Suites
	cipherSuites, err := decodeCipherSuites(data[currOffset:])
	if err != nil {
		return err
	}
	c.cipherSuites = cipherSuites
	currOffset += int(binary.BigEndian.Uint16(data[currOffset:])) + 2

	// Compression Methods
	compressionMethods, err := decodeCompressionMethods(data[currOffset:])
	if err != nil {
		return err
	}
	c.compressionMethods = compressionMethods
	currOffset += int(data[currOffset]) + 1

	// TODO Extensions

	return nil
}
