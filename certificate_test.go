// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/transport/v5/dpipe"
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
		{
			desc: "Simple match in CN",
			localCertificates: []tls.Certificate{
				certificateRandom,
				certificateTest,
				certificateWildcard,
			},
			serverName:          "test.test",
			expectedCertificate: certificateTest,
		},
		{
			desc: "Simple match in SANs",
			localCertificates: []tls.Certificate{
				certificateRandom,
				certificateTest,
				certificateWildcard,
			},
			serverName:          "www.test.test",
			expectedCertificate: certificateTest,
		},

		{
			desc: "Wildcard match",
			localCertificates: []tls.Certificate{
				certificateRandom,
				certificateTest,
				certificateWildcard,
			},
			serverName:          "foo.test.test",
			expectedCertificate: certificateWildcard,
		},
		{
			desc: "No match return first",
			localCertificates: []tls.Certificate{
				certificateRandom,
				certificateTest,
				certificateWildcard,
			},
			serverName:          "foo.bar",
			expectedCertificate: certificateRandom,
		},
		{
			desc: "Get certificate from callback",
			getCertificate: func(*ClientHelloInfo) (*tls.Certificate, error) {
				return &certificateTest, nil
			},
			expectedCertificate: certificateTest,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			cfg := &handshakeConfig{
				localCertificates:   test.localCertificates,
				localGetCertificate: test.getCertificate,
			}
			cert, err := cfg.getCertificate(&ClientHelloInfo{ServerName: test.serverName})
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
		{"RSA request with EC certificate", []clientcertificate.Type{clientcertificate.RSASign}, []tls.Certificate{ecCert}, nil},                      //nolint:lll
		{"EC request with RSA certificate", []clientcertificate.Type{clientcertificate.ECDSASign}, []tls.Certificate{rsaCert}, nil},                   //nolint:lll
		{"select matching certificate", []clientcertificate.Type{clientcertificate.RSASign}, []tls.Certificate{ecCert, rsaCert}, rsaCert.Certificate}, //nolint:lll
		{"matching EC certificate", []clientcertificate.Type{clientcertificate.ECDSASign}, []tls.Certificate{ecCert}, ecCert.Certificate},             //nolint:lll
		{"matching Ed25519 certificate", []clientcertificate.Type{clientcertificate.ECDSASign}, []tls.Certificate{edCert}, edCert.Certificate},        //nolint:lll
		{"RSA request with Ed25519 certificate", []clientcertificate.Type{clientcertificate.RSASign}, []tls.Certificate{edCert}, nil},                 //nolint:lll
		{"unknown certificate type", []clientcertificate.Type{255}, []tls.Certificate{ecCert}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, callback := range []bool{false, true} {
				clientCfg := &Config{InsecureSkipVerify: true, Certificates: tc.certs}
				if callback {
					clientCfg.GetClientCertificate = func(info *CertificateRequestInfo) (*tls.Certificate, error) {
						assert.NotNil(t, info.CertificateTypes)
						for i := range tc.certs {
							if info.SupportsCertificate(&tc.certs[i]) == nil {
								return &tc.certs[i], nil
							}
						}

						return &tls.Certificate{}, nil
					}
				}
				ca, cb := dpipe.Pipe()
				client, err := Client(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), clientCfg)
				require.NoError(t, err)
				defer func() { _ = client.Close() }()
				server, err := Server(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
					Certificates: []tls.Certificate{ecCert}, ClientAuth: RequestClientCert,
					CertificateRequestMessageHook: func(req handshake.MessageCertificateRequest) handshake.Message {
						req.CertificateTypes = tc.types

						return &req
					},
				})
				require.NoError(t, err)
				defer func() { _ = server.Close() }()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				clientResult := make(chan error, 1)
				go func() { clientResult <- client.HandshakeContext(ctx) }()
				serverErr := server.HandshakeContext(ctx)
				clientErr := <-clientResult
				require.NoError(t, clientErr)
				require.NoError(t, serverErr)
				state, ok := server.ConnectionState()
				require.True(t, ok)
				assert.Equal(t, tc.want, state.PeerCertificates)
			}
		})
	}
}
