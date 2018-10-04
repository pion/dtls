package main

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
)

type handshakePayload interface {
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
	handshakePayload handshakePayload
}

func (h handshake) contentType() contentType {
	return contentTypeHandshake
}

func (h *handshake) marshal() ([]byte, error) {
	return nil, nil
}

func (h *handshake) unmarshal(data []byte) error {
	return nil
}
