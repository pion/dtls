package dtls

import "time"

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
	return nil, errNotImplemented
}

func (h *handshake) unmarshal(data []byte) error {
	return errNotImplemented
}

// https://tools.ietf.org/html/rfc4346#section-7.4.1.2
type handshakeRandom struct {
	gmtUnixTime time.Time
	randomBytes [28]byte
}

func (h *handshakeRandom) marshal() ([]byte, error) {
	return nil, errNotImplemented
}

func (h *handshakeRandom) unmarshal(data []byte) error {
	return errNotImplemented
}

// populate fills the handshakeRandom with random values
// may be called multiple times
func (h *handshakeRandom) populate() {
}
