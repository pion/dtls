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

	// SessionID session_id;
	cipherSuites []*cipherSuite
	// CompressionMethod compression_methods<1..2^8-1>;

}

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

	return nil
}
