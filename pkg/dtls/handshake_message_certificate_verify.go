package dtls

type handshakeMessageCertificateVerify struct {
	hashAlgorithm      hashAlgorithm
	signatureAlgorithm signatureAlgorithm
	signature          []byte
}

func (h handshakeMessageCertificateVerify) handshakeType() handshakeType {
	return handshakeTypeCertificateVerify
}

func (h *handshakeMessageCertificateVerify) marshal() ([]byte, error) {
	return nil, nil
}

func (h *handshakeMessageCertificateVerify) unmarshal(data []byte) error {
	return nil
}
