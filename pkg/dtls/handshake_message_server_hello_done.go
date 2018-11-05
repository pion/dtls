package dtls

type handshakeMessageServerHelloDone struct {
}

func (h handshakeMessageServerHelloDone) handshakeType() handshakeType {
	return handshakeTypeServerHelloDone
}

func (h *handshakeMessageServerHelloDone) marshal() ([]byte, error) {
	return []byte{}, nil
}

func (h *handshakeMessageServerHelloDone) unmarshal(data []byte) error {
	return nil
}
