//go:build go1.13
// +build go1.13

package signaturehash

import (
	"crypto/tls"
	"errors"
	"reflect"
	"testing"

	"github.com/pion/dtls/v2/pkg/crypto/hash"
	"github.com/pion/dtls/v2/pkg/crypto/signature"
)

func TestParseSignatureSchemes_Ed25519(t *testing.T) {
	cases := map[string]struct {
		input          []tls.SignatureScheme
		expected       []Algorithm
		err            error
		insecureHashes bool
	}{
		"Translate": {
			input: []tls.SignatureScheme{
				tls.Ed25519,
			},
			expected: []Algorithm{
				{hash.Ed25519, signature.Ed25519},
			},
			err:            nil,
			insecureHashes: false,
		},
	}

	for name, testCase := range cases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			output, err := ParseSignatureSchemes(testCase.input, testCase.insecureHashes)
			if testCase.err != nil && !errors.Is(err, testCase.err) {
				t.Fatalf("Expected error: %v, got: %v", testCase.err, err)
			}
			if !reflect.DeepEqual(testCase.expected, output) {
				t.Errorf("Expected signatureHashAlgorithm:\n%+v\ngot:\n%+v", testCase.expected, output)
			}
		})
	}
}
