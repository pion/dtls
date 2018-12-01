package dtls

import (
	"testing"
)

func TestDecodeCipherSuites(t *testing.T) {
	testCases := []struct {
		buf    []byte
		result []*cipherSuite
		err    error
	}{
		{[]byte{}, nil, errDTLSPacketInvalidLength},
	}

	for _, testCase := range testCases {
		_, err := decodeCipherSuites(testCase.buf)
		if err != testCase.err {
			t.Fatal("Unexpected error", err)
		}
		// todo: compare result
	}

}
