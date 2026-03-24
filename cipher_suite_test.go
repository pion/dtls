// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"testing"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v4/dpipe"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
)

func TestCipherSuiteName(t *testing.T) {
	testCases := []struct {
		suite    CipherSuiteID
		expected string
	}{
		{TLS_ECDHE_ECDSA_WITH_AES_128_CCM, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"},
		{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
		{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
		{TLS_PSK_WITH_CHACHA20_POLY1305_SHA256, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"},
		{CipherSuiteID(0x0000), "0x0000"},
	}

	for _, testCase := range testCases {
		assert.Equal(t, testCase.expected, CipherSuiteName(testCase.suite))
	}
}

func TestAllCipherSuites(t *testing.T) {
	assert.NotEmpty(t, allCipherSuites())
}

// CustomCipher that is just used to assert Custom IDs work.
type testCustomCipherSuite struct {
	ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256
	authenticationType CipherSuiteAuthenticationType
}

func (t *testCustomCipherSuite) ID() CipherSuiteID {
	return 0xFFFF
}

func (t *testCustomCipherSuite) AuthenticationType() CipherSuiteAuthenticationType {
	return t.authenticationType
}

// Assert that two connections that pass in a CipherSuite with a CustomID works.
func TestCustomCipherSuite(t *testing.T) {
	type result struct {
		c   *Conn
		err error
	}

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	runTest := func(cipherFactory func() []CipherSuite) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		resultCh := make(chan result)

		go func() {
			client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
				CipherSuites:       []CipherSuiteID{},
				CustomCipherSuites: cipherFactory,
			}, true)
			resultCh <- result{client, err}
		}()

		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
			CipherSuites:       []CipherSuiteID{},
			CustomCipherSuites: cipherFactory,
		}, true)

		clientResult := <-resultCh
		assert.NoError(t, err)
		assert.NoError(t, server.Close())
		assert.Nil(t, clientResult.err)
		assert.NoError(t, clientResult.c.Close())
	}

	t.Run("Custom ID", func(*testing.T) {
		runTest(func() []CipherSuite {
			return []CipherSuite{&testCustomCipherSuite{authenticationType: CipherSuiteAuthenticationTypeCertificate}}
		})
	})

	t.Run("Anonymous Cipher", func(*testing.T) {
		runTest(func() []CipherSuite {
			return []CipherSuite{&testCustomCipherSuite{authenticationType: CipherSuiteAuthenticationTypeAnonymous}}
		})
	})
}
