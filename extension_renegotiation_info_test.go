package dtls

import "testing"

func TestRenegotiationInfo(t *testing.T) {
	extension := extensionRenegotiationInfo{renegotiatedConnection: 0}

	raw, err := extension.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	newExtension := extensionRenegotiationInfo{}
	err = newExtension.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	if newExtension.renegotiatedConnection != extension.renegotiatedConnection {
		t.Errorf("extensionRenegotiationInfo marshal: got %d expected %d", newExtension.renegotiatedConnection, extension.renegotiatedConnection)
	}
}
