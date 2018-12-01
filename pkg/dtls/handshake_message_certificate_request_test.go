package dtls

import (
	"reflect"
	"testing"
)

func TestHandshakeMessageCertificateRequest(t *testing.T) {
	rawCertificateRequest := []byte{}
	parsedCertificateRequest := &handshakeMessageCertificateRequest{}

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
