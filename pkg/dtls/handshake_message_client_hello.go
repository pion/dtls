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
type clientHello struct {
	messageSequence uint16
	fragmentOffset  uint32
	fragmentLength  uint32

	version protocolVersion
	random  handshakeRandom

	cipherSuites       []*cipherSuite
	compressionMethods []*compressionMethod
}

const clientHelloVariableWidthStart = 46

func (c clientHello) handshakeType() handshakeType {
	return handshakeTypeClientHello
}

func (c *clientHello) marshal() ([]byte, error) {
	return nil, errNotImplemented
}

func (c *clientHello) unmarshal(data []byte) error {
	if handshakeType(data[0]) != c.handshakeType() {
		return errInvalidHandshakeType
	}
	if (len(data) - handshakeMessageAssumedLen) != int(binary.BigEndian.Uint16(data[2:])) {
		return errLengthMismatch
	}

	c.messageSequence = binary.BigEndian.Uint16(data[4:])
	c.fragmentOffset = bigEndianUint24(data[6:])
	c.fragmentLength = bigEndianUint24(data[9:])

	c.version.major = data[12]
	c.version.minor = data[13]

	if err := c.random.unmarshal(data[14 : 14+handshakeRandomLength]); err != nil {
		return err
	}

	// rest of packet has variable width sections
	currOffset := clientHelloVariableWidthStart
	currOffset += int(data[currOffset]) + 1 // SessionID
	currOffset += int(data[currOffset]) + 1 // Cookie

	// Cipher Suites
	cipherSuitesCount := int(binary.BigEndian.Uint16(data[currOffset:])) / 2
	for i := 0; i < cipherSuitesCount; i++ {
		currOffset += 2
		id := cipherSuiteID(binary.BigEndian.Uint16(data[currOffset:]))
		if cipherSuite, ok := cipherSuites[id]; ok {
			c.cipherSuites = append(c.cipherSuites, cipherSuite)
		}
	}
	if cipherSuitesCount != 0 {
		currOffset += 2
	}

	// Compression Methods
	compressionMethodsCount := int(data[currOffset])
	for i := 0; i < compressionMethodsCount; i++ {
		currOffset++
		id := compressionMethodID(data[currOffset])
		if compressionMethod, ok := compressionMethods[id]; ok {
			c.compressionMethods = append(c.compressionMethods, compressionMethod)
		}
	}
	if compressionMethodsCount != 0 {
		currOffset++
	}

	// Extensions

	return nil
}
