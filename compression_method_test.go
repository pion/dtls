package dtls

import (
	"errors"
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
		if !errors.Is(err, testCase.err) {
			t.Fatal("Unexpected error", err)
		}
	}
}
