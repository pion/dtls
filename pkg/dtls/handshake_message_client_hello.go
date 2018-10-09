package dtls

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
	// CipherSuite cipher_suites<2..2^16-1>;
	// CompressionMethod compression_methods<1..2^8-1>;

}

func (c clientHello) handshakeType() handshakeType {
	return handshakeTypeClientHello
}

func (c *clientHello) marshal() ([]byte, error) {
	return nil, errNotImplemented
}

func (c *clientHello) unmarshal(data []byte) error {
	return errNotImplemented
}
