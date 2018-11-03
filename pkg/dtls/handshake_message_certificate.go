package dtls

import (
	"crypto/x509"
)

/*
When a client first connects to a server it is required to send
the client hello as its first message.  The client can also send a
client hello in response to a hello request or on its own
initiative in order to renegotiate the security parameters in an
existing connection.
*/
type handshakeMessageCertificate struct {
	certificate *x509.Certificate
}

func (h handshakeMessageCertificate) handshakeType() handshakeType {
	return handshakeTypeCertificate
}

func (h *handshakeMessageCertificate) marshal() ([]byte, error) {
	if h.certificate == nil {
		return nil, errCertificateUnset
	}

	out := make([]byte, 3)
	putBigEndianUint24(out, uint32(len(h.certificate.Raw)))

	return append(out, h.certificate.Raw...), nil
}

func (h *handshakeMessageCertificate) unmarshal(data []byte) error {
	certificateLen := int(bigEndianUint24(data))
	if certificateLen+3 != len(data) {
		return errLengthMismatch
	}

	cert, err := x509.ParseCertificate(data[3:])
	if err != nil {
		return err
	}
	h.certificate = cert

	return nil
}
