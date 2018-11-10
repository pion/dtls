package dtls

type handshakeMessageFinished struct {
	verifyData []byte
}

func (h handshakeMessageFinished) handshakeType() handshakeType {
	return handshakeTypeFinished
}

func (h *handshakeMessageFinished) marshal() ([]byte, error) {
	return append([]byte{}, h.verifyData...), nil
}

func (h *handshakeMessageFinished) unmarshal(data []byte) error {
	h.verifyData = append([]byte{}, data...)
	return nil
}
