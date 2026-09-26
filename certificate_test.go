// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"testing"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	"github.com/pion/dtls/v4/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
)

func TestGetCertificate(t *testing.T) {
	certificateWildcard, err := selfsign.GenerateSelfSignedWithDNS("*.test.test")
	assert.NoError(t, err)

	certificateTest, err := selfsign.GenerateSelfSignedWithDNS("test.test", "www.test.test", "pop.test.test")
	assert.NoError(t, err)

	certificateRandom, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	testCases := []struct {
		localCertificates   []tls.Certificate
		desc                string
		serverName          string
		expectedCertificate tls.Certificate
		getCertificate      func(info *ClientHelloInfo) (*tls.Certificate, error)
	}{
		{desc: "Simple match in CN", localCertificates: []tls.Certificate{certificateRandom, certificateTest, certificateWildcard}, serverName: "test.test", expectedCertificate: certificateTest},
		{desc: "Simple match in SANs", localCertificates: []tls.Certificate{certificateRandom, certificateTest, certificateWildcard}, serverName: "www.test.test", expectedCertificate: certificateTest},

		{desc: "Wildcard match", localCertificates: []tls.Certificate{certificateRandom, certificateTest, certificateWildcard}, serverName: "foo.test.test", expectedCertificate: certificateWildcard},
		{desc: "No match return first", localCertificates: []tls.Certificate{certificateRandom, certificateTest, certificateWildcard}, serverName: "foo.bar", expectedCertificate: certificateRandom},
		{desc: "Get certificate from callback", getCertificate: func(*ClientHelloInfo) (*tls.Certificate, error) { return &certificateTest, nil }, expectedCertificate: certificateTest},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			getCertificate := func(info *dtlsconfig.ClientHelloInfo) (*tls.Certificate, error) {
				return test.getCertificate(&ClientHelloInfo{ServerName: info.ServerName, CipherSuites: info.CipherSuites, RandomBytes: info.RandomBytes})
			}
			if test.getCertificate == nil {
				getCertificate = nil
			}

			cfg := &dtlsconfig.HandshakeConfig{
				LocalCertificates:   test.localCertificates,
				LocalGetCertificate: getCertificate,
			}
			cert, err := cfg.GetCertificate(&dtlsconfig.ClientHelloInfo{ServerName: test.serverName})
			assert.NoError(t, err)
			assert.Equal(t, test.expectedCertificate.Leaf, cert.Leaf, "Certificate Leaf should match expected")
		})
	}
}

func TestClientCertificateTypes(t *testing.T) {
	ecCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	rsaCert, err := selfsign.SelfSign(rsaKey)
	assert.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	edCert, err := selfsign.SelfSign(edKey)
	assert.NoError(t, err)
	for _, tc := range []struct {
		name  string
		types []clientcertificate.Type
		certs []tls.Certificate
		want  [][]byte
	}{
		{"RSA request with EC certificate", []clientcertificate.Type{clientcertificate.RSASign}, []tls.Certificate{ecCert}, nil},
		{"EC request with RSA certificate", []clientcertificate.Type{clientcertificate.ECDSASign}, []tls.Certificate{rsaCert}, nil},
		{"select matching certificate", []clientcertificate.Type{clientcertificate.RSASign}, []tls.Certificate{ecCert, rsaCert}, rsaCert.Certificate},
		{"matching EC certificate", []clientcertificate.Type{clientcertificate.ECDSASign}, []tls.Certificate{ecCert}, ecCert.Certificate},
		{"matching Ed25519 certificate", []clientcertificate.Type{clientcertificate.ECDSASign}, []tls.Certificate{edCert}, edCert.Certificate},
		{"RSA request with Ed25519 certificate", []clientcertificate.Type{clientcertificate.RSASign}, []tls.Certificate{edCert}, nil},
		{"unknown certificate type", []clientcertificate.Type{255}, []tls.Certificate{ecCert}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, callback := range []bool{false, true} {
				clientOpts := []ClientOption{WithInsecureSkipVerify(true), WithMaxVersion(protocol.Version1_2), WithCertificates(tc.certs...)}
				if callback {
					clientOpts = append(clientOpts, WithGetClientCertificate(func(info *CertificateRequestInfo) (*tls.Certificate, error) {
						assert.NotNil(t, info.CertificateTypes)
						for i := range tc.certs {
							if info.SupportsCertificate(&tc.certs[i]) == nil {
								return &tc.certs[i], nil
							}
						}

						return &tls.Certificate{}, nil
					}))
				}
				client, server := handshakePair(t, clientOpts, []ServerOption{
					WithCertificates(ecCert), WithMaxVersion(protocol.Version1_2), WithClientAuth(RequestClientCert),
					WithCertificateRequestMessageHook(func(req handshake.MessageCertificateRequest) handshake.Message {
						req.CertificateTypes = tc.types

						return &req
					}),
				})
				assert.NoError(t, client.configErr)
				assert.NoError(t, server.configErr)
				assert.NoError(t, client.handshakeError)
				assert.NoError(t, server.handshakeError)
				state, ok := server.conn.ConnectionState()
				assert.True(t, ok)
				assert.Equal(t, tc.want, state.PeerCertificates)
			}
		})
	}
}
