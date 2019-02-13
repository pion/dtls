package dtls

import (
	"reflect"
	"testing"
)

func TestExtensionSupportedSignatureAlgorithms(t *testing.T) {

	rawExtensionSupportedSignatureAlgorithms := []byte{
		0x00, 0x0d,
		0x00, 0x08,
		0x00, 0x06,
		0x04, 0x03,
		0x05, 0x03,
		0x06, 0x03,
	}
	parsedExtensionSupportedSignatureAlgorithms := &extensionSupportedSignatureAlgorithms{
		signatureHashAlgorithms: []signatureHashAlgorithm{
			{HashAlgorithmSHA256, signatureAlgorithmECDSA},
			{HashAlgorithmSHA384, signatureAlgorithmECDSA},
			{HashAlgorithmSHA512, signatureAlgorithmECDSA},
		},
	}

	raw, err := parsedExtensionSupportedSignatureAlgorithms.Marshal()
	if err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(raw, rawExtensionSupportedSignatureAlgorithms) {
		t.Errorf("extensionSupportedSignatureAlgorithms marshal: got %#v, want %#v", raw, rawExtensionSupportedSignatureAlgorithms)
	}
}
