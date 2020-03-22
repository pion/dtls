// +build go1.13

package dtls

import (
	"crypto/tls"
	"reflect"
	"testing"

	"golang.org/x/xerrors"
)

func TestParseSignatureSchemes_Ed25519(t *testing.T) {
	cases := map[string]struct {
		input          []tls.SignatureScheme
		expected       []signatureHashAlgorithm
		err            error
		insecureHashes bool
	}{
		"Translate": {
			input: []tls.SignatureScheme{
				tls.Ed25519,
			},
			expected: []signatureHashAlgorithm{
				{hashAlgorithmEd25519, signatureAlgorithmEd25519},
			},
			err:            nil,
			insecureHashes: false,
		},
	}

	for name, testCase := range cases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			output, err := parseSignatureSchemes(testCase.input, testCase.insecureHashes)
			if testCase.err != nil && !xerrors.Is(err, testCase.err) {
				t.Fatalf("Expected error: %v, got: %v", testCase.err, err)
			}
			if !reflect.DeepEqual(testCase.expected, output) {
				t.Errorf("Expected signatureHashAlgorithm:\n%+v\ngot:\n%+v", testCase.expected, output)
			}
		})
	}
}
