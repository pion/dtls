// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"testing"
	"time"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestClientCertificateSignatureSchemes(t *testing.T) {
	ecdsaCertificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaCertificate, err := selfsign.SelfSign(key)
	require.NoError(t, err)

	for _, testCase := range []struct {
		name     string
		version  protocol.Version
		scheme   tls.SignatureScheme
		callback bool
	}{
		{"DTLS12/automatic", protocol.Version1_2, tls.PKCS1WithSHA256, false},
		{"DTLS12/callback", protocol.Version1_2, tls.PKCS1WithSHA256, true},
		{"DTLS13/automatic", protocol.Version1_3, tls.PSSWithSHA256, false},
		{"DTLS13/callback", protocol.Version1_3, tls.PSSWithSHA256, true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			clientTransport, serverTransport := packetPipe()
			t.Cleanup(func() { _ = clientTransport.Close(); _ = serverTransport.Close() })
			clientOptions := []ClientOption{
				WithCertificates(ecdsaCertificate, rsaCertificate), WithInsecureSkipVerify(true),
				WithMinVersion(testCase.version), WithMaxVersion(testCase.version),
			}
			requests := make(chan *CertificateRequestInfo, 1)
			if testCase.callback {
				clientOptions = append(clientOptions, WithGetClientCertificate(func(info *CertificateRequestInfo) (*tls.Certificate, error) {
					requests <- info

					for _, certificate := range []*tls.Certificate{&ecdsaCertificate, &rsaCertificate} {
						if info.SupportsCertificate(certificate) == nil {
							return certificate, nil
						}
					}

					return &tls.Certificate{}, nil
				}))
			}
			client, err := Client(clientTransport, clientTransport.RemoteAddr(), clientOptions...)
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })
			server, err := Server(serverTransport, serverTransport.RemoteAddr(), WithCertificates(rsaCertificate), WithClientAuth(RequireAnyClientCert),
				WithSignatureSchemes(testCase.scheme), WithMinVersion(testCase.version), WithMaxVersion(testCase.version))
			require.NoError(t, err)
			t.Cleanup(func() { _ = server.Close() })

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			errs := make(chan error, 2)
			go func() { errs <- client.HandshakeContext(ctx) }()
			go func() { errs <- server.HandshakeContext(ctx) }()
			require.NoError(t, <-errs)
			require.NoError(t, <-errs)
			state, ok := server.ConnectionState()
			require.True(t, ok)
			require.Equal(t, rsaCertificate.Certificate, state.PeerCertificates)
			if testCase.callback {
				select {
				case info := <-requests:
					require.Equal(t, []tls.SignatureScheme{testCase.scheme}, info.SignatureSchemes)
					require.Equal(t, testCase.version, info.version)
				default:
					require.FailNow(t, "client certificate callback was not called")
				}
			}
		})
	}
}
