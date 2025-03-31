// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/dsa" //nolint:staticcheck
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/stretchr/testify/assert"
)

func TestValidateConfig(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		assert.NoError(t, err, "TestValidateConfig: Config validation error, self signed certificate not generated")

		return
	}
	dsaPrivateKey := &dsa.PrivateKey{}
	err = dsa.GenerateParameters(&dsaPrivateKey.Parameters, rand.Reader, dsa.L1024N160)
	if err != nil {
		assert.NoError(t, err, "TestValidateConfig: Config validation error, DSA parameters not generated")

		return
	}
	err = dsa.GenerateKey(dsaPrivateKey, rand.Reader)
	if err != nil {
		assert.NoError(t, err, "TestValidateConfig: Config validation error, DSA private key not generated")

		return
	}
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		assert.NoError(t, err, "TestValidateConfig: Config validation error, RSA private key not generated")

		return
	}
	cases := map[string]struct {
		config     *Config
		wantAnyErr bool
		expErr     error
	}{
		"Empty config": {
			expErr: errNoConfigProvided,
		},
		"PSK and Certificate, valid cipher suites": {
			config: &Config{
				CipherSuites: []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				PSK: func([]byte) ([]byte, error) {
					return nil, nil
				},
				Certificates: []tls.Certificate{cert},
			},
		},
		"PSK and Certificate, no PSK cipher suite": {
			config: &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				PSK: func([]byte) ([]byte, error) {
					return nil, nil
				},
				Certificates: []tls.Certificate{cert},
			},
			expErr: errNoAvailablePSKCipherSuite,
		},
		"PSK and Certificate, no non-PSK cipher suite": {
			config: &Config{
				CipherSuites: []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM_8},
				PSK: func([]byte) ([]byte, error) {
					return nil, nil
				},
				Certificates: []tls.Certificate{cert},
			},
			expErr: errNoAvailableCertificateCipherSuite,
		},
		"PSK identity hint with not PSK": {
			config: &Config{
				CipherSuites:    []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				PSK:             nil,
				PSKIdentityHint: []byte{},
			},
			expErr: errIdentityNoPSK,
		},
		"Invalid private key": {
			config: &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: dsaPrivateKey}},
			},
			expErr: errInvalidPrivateKey,
		},
		"PrivateKey without Certificate": {
			config: &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				Certificates: []tls.Certificate{{PrivateKey: cert.PrivateKey}},
			},
			expErr: errInvalidCertificate,
		},
		"Invalid cipher suites": {
			config:     &Config{CipherSuites: []CipherSuiteID{0x0000}},
			wantAnyErr: true,
		},
		"Valid config": {
			config: &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				Certificates: []tls.Certificate{cert, {Certificate: cert.Certificate, PrivateKey: rsaPrivateKey}},
			},
		},
		"Valid config with get certificate": {
			config: &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				GetCertificate: func(*ClientHelloInfo) (*tls.Certificate, error) {
					return &tls.Certificate{Certificate: cert.Certificate, PrivateKey: rsaPrivateKey}, nil
				},
			},
		},
		"Valid config with get client certificate": {
			config: &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				GetClientCertificate: func(*CertificateRequestInfo) (*tls.Certificate, error) {
					return &tls.Certificate{Certificate: cert.Certificate, PrivateKey: rsaPrivateKey}, nil
				},
			},
		},
	}

	for name, testCase := range cases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			err := validateConfig(testCase.config)
			if testCase.expErr != nil || testCase.wantAnyErr {
				if testCase.expErr != nil && !errors.Is(err, testCase.expErr) {
					assert.ErrorIs(t, err, testCase.expErr, "TestValidateConfig")
				}
				assert.Error(t, err, "TestValidateConfig: Config validation expected an error")
			}
		})
	}
}
