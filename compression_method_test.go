package dtls

import (
	"testing"
)

func TestDecodeCompressionMethods(t *testing.T) {

	testCases := []struct {
		buf    []byte
		result []*compressionMethod
		err    error
	}{
		{[]byte{}, nil, errDTLSPacketInvalidLength},
	}

	for _, testCase := range testCases {
		_, err := decodeCompressionMethods(testCase.buf)
		if err != testCase.err {
			t.Fatal("Unexpected error", err)
		}
		// todo: compare result
	}

}
