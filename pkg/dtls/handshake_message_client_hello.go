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
	version protocolVersion
	random  handshakeRandom

	cipherSuites       []*cipherSuite
	compressionMethods []*compressionMethod
}

const clientHelloVariableWidthStart = 34

func (c clientHello) handshakeType() handshakeType {
	return handshakeTypeClientHello
}

func (c *clientHello) marshal() ([]byte, error) {
	out := make([]byte, clientHelloVariableWidthStart)
	out[0] = c.version.major
	out[1] = c.version.minor

	rand, err := c.random.marshal()
	if err != nil {
		return nil, err
	}
	copy(out[2:], rand)

	out = append(out, 0x00) // SessionID
	out = append(out, 0x00) // Cookie

	out = append(out, []byte{0x00, 0x00}...)
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(c.cipherSuites)*2))
	for i := len(c.cipherSuites); i > 0; i-- {
		out = append(out, []byte{0x00, 0x00}...)
		binary.BigEndian.PutUint16(out[len(out)-2:], uint16(c.cipherSuites[i-1].id))
	}

	out = append(out, byte(len(c.compressionMethods)))
	for i := len(c.compressionMethods); i > 0; i-- {
		out = append(out, byte(c.compressionMethods[i-1].id))
	}
	return out, nil
}

func (c *clientHello) unmarshal(data []byte) error {
	c.version.major = data[0]
	c.version.minor = data[1]

	if err := c.random.unmarshal(data[2 : 2+handshakeRandomLength]); err != nil {
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
