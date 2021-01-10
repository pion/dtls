package dtls

import (
	"testing"
)

func TestCipherSuiteName(t *testing.T) {
	testCases := []struct {
		suite    CipherSuiteID
		expected string
	}{
		{TLS_ECDHE_ECDSA_WITH_AES_128_CCM, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"},
		{CipherSuiteID(0x0000), "0x0000"},
	}

	for _, testCase := range testCases {
		res := CipherSuiteName(testCase.suite)
		if res != testCase.expected {
			t.Fatalf("Expected: %s, got %s", testCase.expected, res)
		}
	}
}

func TestAllCipherSuites(t *testing.T) {
	actual := len(allCipherSuites())
	if actual == 0 {
		t.Fatal()
	}
}
