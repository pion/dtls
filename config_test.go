// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/dsa" //nolint:staticcheck
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v4/dpipe"
	"github.com/stretchr/testify/assert"
)

func clientConfigError(t *testing.T, opts ...ClientOption) error {
	t.Helper()

	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	client, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts...)
	if client != nil {
		_ = client.Close()
	}

	return err
}

func serverConfigError(t *testing.T, opts ...ServerOption) error {
	t.Helper()

	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	server, err := ServerWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts...)
	if server != nil {
		_ = server.Close()
	}

	return err
}

func TestConfigOptions(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		assert.NoError(t, err, "TestConfigOptions: self signed certificate not generated")

		return
	}
	dsaPrivateKey := &dsa.PrivateKey{}
	err = dsa.GenerateParameters(&dsaPrivateKey.Parameters, rand.Reader, dsa.L1024N160)
	if err != nil {
		assert.NoError(t, err, "TestConfigOptions: DSA parameters not generated")

		return
	}
	err = dsa.GenerateKey(dsaPrivateKey, rand.Reader)
	if err != nil {
		assert.NoError(t, err, "TestConfigOptions: DSA private key not generated")

		return
	}
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		assert.NoError(t, err, "TestConfigOptions: RSA private key not generated")

		return
	}
	cases := map[string]struct {
		validate   func(*testing.T) error
		wantAnyErr bool
		expErr     error
	}{
		"psk and Certificate, valid cipher suites": {
			validate: func(t *testing.T) error {
				t.Helper()

				return serverConfigError(t,
					WithCipherSuites(TLS_PSK_WITH_AES_128_CCM_8, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
					WithPSK(func([]byte) ([]byte, error) { return nil, nil }),
					WithCertificates(cert),
				)
			},
		},
		"psk and Certificate, no psk cipher suite": {
			validate: func(t *testing.T) error {
				t.Helper()

				return serverConfigError(t,
					WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
					WithPSK(func([]byte) ([]byte, error) { return nil, nil }),
					WithCertificates(cert),
				)
			},
			expErr: dtlserrors.ErrNoAvailablePSKCipherSuite,
		},
		"psk and Certificate, no non-psk cipher suite": {
			validate: func(t *testing.T) error {
				t.Helper()

				return serverConfigError(t,
					WithCipherSuites(TLS_PSK_WITH_AES_128_CCM_8),
					WithPSK(func([]byte) ([]byte, error) { return nil, nil }),
					WithCertificates(cert),
				)
			},
			expErr: dtlserrors.ErrNoAvailableCertificateCipherSuite,
		},
		"psk identity hint with not psk": {
			validate: func(t *testing.T) error {
				t.Helper()

				return serverConfigError(t,
					WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
					WithPSKIdentityHint([]byte{}),
				)
			},
			expErr: dtlserrors.ErrIdentityNoPSK,
		},
		"Invalid private key": {
			validate: func(t *testing.T) error {
				t.Helper()

				return clientConfigError(t,
					WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
					WithCertificates(tls.Certificate{Certificate: cert.Certificate, PrivateKey: dsaPrivateKey}),
				)
			},
			expErr: dtlserrors.ErrInvalidPrivateKey,
		},
		"PrivateKey without Certificate": {
			validate: func(t *testing.T) error {
				t.Helper()

				return clientConfigError(t,
					WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
					WithCertificates(tls.Certificate{PrivateKey: cert.PrivateKey}),
				)
			},
			expErr: dtlserrors.ErrInvalidCertificate,
		},
		"Invalid cipher suites": {
			validate: func(t *testing.T) error {
				t.Helper()

				return clientConfigError(t, WithCipherSuites(0x0000))
			},
			wantAnyErr: true,
		},
		"Valid config": {
			validate: func(t *testing.T) error {
				t.Helper()

				return clientConfigError(t,
					WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
					WithCertificates(cert, tls.Certificate{Certificate: cert.Certificate, PrivateKey: rsaPrivateKey}),
				)
			},
		},
		"Valid config with get certificate": {
			validate: func(t *testing.T) error {
				t.Helper()

				return serverConfigError(t,
					WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
					WithGetCertificate(func(*ClientHelloInfo) (*tls.Certificate, error) {
						return &tls.Certificate{Certificate: cert.Certificate, PrivateKey: rsaPrivateKey}, nil
					}),
				)
			},
		},
		"Valid config with get client certificate": {
			validate: func(t *testing.T) error {
				t.Helper()

				return clientConfigError(t,
					WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
					WithGetClientCertificate(func(*CertificateRequestInfo) (*tls.Certificate, error) {
						return &tls.Certificate{Certificate: cert.Certificate, PrivateKey: rsaPrivateKey}, nil
					}),
				)
			},
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			err := testCase.validate(t)
			if testCase.expErr != nil || testCase.wantAnyErr {
				if testCase.expErr != nil && !errors.Is(err, testCase.expErr) {
					assert.ErrorIs(t, err, testCase.expErr, "TestConfigOptions")
				}
				assert.Error(t, err, "TestConfigOptions: validation expected an error")
			} else {
				assert.NoError(t, err, "TestConfigOptions")
			}
		})
	}
}
