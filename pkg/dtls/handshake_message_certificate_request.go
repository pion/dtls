package dtls

/*
A non-anonymous server can optionally request a certificate from
the client, if appropriate for the selected cipher suite.  This
message, if sent, will immediately follow the ServerKeyExchange
message (if it is sent; otherwise, this message follows the
server's Certificate message).
*/

type handshakeMessageCertificateRequest struct {
}

func (h handshakeMessageCertificateRequest) handshakeType() handshakeType {
	return handshakeTypeCertificateRequest
}

func (h *handshakeMessageCertificateRequest) Marshal() ([]byte, error) {
	// TODO
	return []byte{}, nil
}

func (h *handshakeMessageCertificateRequest) Unmarshal(data []byte) error {
	// TODO
	return nil
}
