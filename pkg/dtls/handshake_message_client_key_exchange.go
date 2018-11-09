package dtls

type handshakeMessageClientKeyExchange struct {
	publicKey []byte
}

func (h handshakeMessageClientKeyExchange) handshakeType() handshakeType {
	return handshakeTypeClientKeyExchange
}

func (h *handshakeMessageClientKeyExchange) marshal() ([]byte, error) {
	return append([]byte{byte(len(h.publicKey))}, h.publicKey...), nil
}

func (h *handshakeMessageClientKeyExchange) unmarshal(data []byte) error {
	publicKeyLength := int(data[0])
	if len(data) <= publicKeyLength {
		return errBufferTooSmall
	}
	h.publicKey = append([]byte{}, data[1:]...)
	return nil
}
