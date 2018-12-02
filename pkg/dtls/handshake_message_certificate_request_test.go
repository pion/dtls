package dtls

import (
	"reflect"
	"testing"
)

func TestHandshakeMessageCertificateRequest(t *testing.T) {
	rawCertificateRequest := []byte{
		0x02, 0x01, 0x40, 0x00, 0x0C, 0x04, 0x03, 0x04, 0x01, 0x05,
		0x03, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x00, 0x00,
	}
	parsedCertificateRequest := &handshakeMessageCertificateRequest{
		certificateTypes: []clientCertificateType{
			clientCertificateTypeRSASign,
			clientCertificateTypeECDSASign,
		},
		signatureHashAlgorithms: []signatureHashAlgorithm{
			{hash: HashAlgorithmSHA256, signature: signatureAlgorithmECDSA},
			{hash: HashAlgorithmSHA256, signature: signatureAlgorithmRSA},
			{hash: HashAlgorithmSHA384, signature: signatureAlgorithmECDSA},
			{hash: HashAlgorithmSHA384, signature: signatureAlgorithmRSA},
			{hash: HashAlgorithmSHA512, signature: signatureAlgorithmRSA},
			{hash: HashAlgorithmSHA1, signature: signatureAlgorithmRSA},
		},
	}

	c := &handshakeMessageCertificateRequest{}
	if err := c.Unmarshal(rawCertificateRequest); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(c, parsedCertificateRequest) {
		t.Errorf("parsedCertificateRequest unmarshal: got %#v, want %#v", c, parsedCertificateRequest)
	}

	raw, err := c.Marshal()
	if err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(raw, rawCertificateRequest) {
		t.Errorf("parsedCertificateRequest marshal: got %#v, want %#v", raw, rawCertificateRequest)
	}
}
