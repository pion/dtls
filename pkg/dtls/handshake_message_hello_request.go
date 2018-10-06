package dtls

// HelloRequest is a simple notification that the client should begin
// the negotiation process anew In response, the client should send
// a ClientHello message when convenient.  This message is not
// intended to establish which side is the client or server but
// merely to initiate a new negotiation.
// https://tools.ietf.org/html/rfc5246#section-7.4.1.1
type helloRequest struct {
}

func (h helloRequest) handshakeType() handshakeType {
	return handshakeTypeHelloRequest
}

func (h *helloRequest) marshal() ([]byte, error) {
	return nil, errNotImplemented
}

func (h *helloRequest) unmarshal(data []byte) error {
	return errNotImplemented
}
