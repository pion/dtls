package dtls

import (
	"crypto/tls"
	"errors"
	"reflect"
	"testing"

	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
)

func TestGetCertificate(t *testing.T) {
	certificateWildcard, err := selfsign.GenerateSelfSignedWithDNS("*.test.test")
	if err != nil {
		t.Fatal(err)
	}

	certificateTest, err := selfsign.GenerateSelfSignedWithDNS("test.test", "www.test.test", "pop.test.test")
	if err != nil {
		t.Fatal(err)
	}

	certificateRandom, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &handshakeConfig{
		localCertificates: []tls.Certificate{
			certificateRandom,
			certificateTest,
			certificateWildcard,
		},
	}

	testCases := []struct {
		desc                string
		serverName          string
		expectedCertificate tls.Certificate
	}{
		{
			desc:                "Simple match in CN",
			serverName:          "test.test",
			expectedCertificate: certificateTest,
		},
		{
			desc:                "Simple match in SANs",
			serverName:          "www.test.test",
			expectedCertificate: certificateTest,
		},

		{
			desc:                "Wildcard match",
			serverName:          "foo.test.test",
			expectedCertificate: certificateWildcard,
		},
		{
			desc:                "No match return first",
			serverName:          "foo.bar",
			expectedCertificate: certificateRandom,
		},
	}

	for _, test := range testCases {
		test := test

		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			cert, err := cfg.getCertificate(test.serverName)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(cert.Leaf, test.expectedCertificate.Leaf) {
				t.Fatalf("Certificate does not match: expected(%v) actual(%v)", test.expectedCertificate.Leaf, cert.Leaf)
			}
		})
	}
}

func TestGetCertificateEmpty(t *testing.T) {
	cfg := &handshakeConfig{}
	_, err := cfg.getCertificate("test")
	if err != errNoCertificates {
		t.Fatalf("getCertificate should return errNoCertificates")
	}
}

func TestGetCertificateFunc(t *testing.T) {
	certMap := map[string]*tls.Certificate{
		"pop.test.test": nil,
		"test.test":     nil,
	}
	for k := range certMap {
		cert, err := selfsign.GenerateSelfSignedWithDNS(k)
		if err != nil {
			t.Fatal(err)
		}
		certMap[k] = &cert
	}
	getCertFunc := func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, ok := certMap[chi.ServerName]
		if !ok {
			return nil, errors.New("no cert found")
		}
		return cert, nil
	}

	cfg := &handshakeConfig{
		getCertificateFunc: getCertFunc,
	}

	testCases := []struct {
		desc                string
		serverName          string
		expectedCertificate *tls.Certificate
	}{
		{
			desc:                "Simple match in CN",
			serverName:          "test.test",
			expectedCertificate: certMap["test.test"],
		},
		{
			desc:                "Simple match in SANs",
			serverName:          "pop.test.test",
			expectedCertificate: certMap["pop.test.test"],
		},
		{
			desc:                "No match return error",
			serverName:          "foo.bar",
			expectedCertificate: nil,
		},
	}

	for _, test := range testCases {
		test := test

		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			cert, err := cfg.getCertificate(test.serverName)
			if test.expectedCertificate != nil && err != nil {
				t.Fatal(err)
			}
			if test.expectedCertificate == nil {
				if err == nil {
					t.Fatalf("Expected error on nil expectedCertificate")
				}
				return
			}

			if !reflect.DeepEqual(cert.Leaf, test.expectedCertificate.Leaf) {
				t.Fatalf("Certificate does not match: expected(%v) actual(%v)", test.expectedCertificate.Leaf, cert.Leaf)
			}
		})
	}
}
