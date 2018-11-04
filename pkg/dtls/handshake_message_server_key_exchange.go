package dtls

// Structure only supports ECDH
type handshakeMessageServerKeyExchange struct {
	ellipticCurveType  ellipticCurveType
	namedCurve         namedCurve
	publicKey          []byte
	signatureAlgorithm signatureAlgorithm
	hashAlgorithm      hashAlgorithm
	signature          []byte
}

func (h handshakeMessageServerKeyExchange) handshakeType() handshakeType {
	return handshakeTypeServerKeyExchange
}

func (h *handshakeMessageServerKeyExchange) marshal() ([]byte, error) {
	return nil, errNotImplemented
}

func (h *handshakeMessageServerKeyExchange) unmarshal(data []byte) error {
	return errNotImplemented
}
