// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"testing"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/transport/v4/dpipe"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCipherSuiteName(t *testing.T) {
	testCases := []struct {
		suite    CipherSuiteID
		expected string
	}{
		{TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"},
		{TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"},
		{TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256"},
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

func TestInsecureCipherSuites(t *testing.T) {
	assert.Empty(t, InsecureCipherSuites(), "Expected no insecure ciphersuites")
}

func TestCipherSuites(t *testing.T) {
	ours := allCipherSuites()
	theirs := CipherSuites()
	assert.Equal(t, len(ours), len(theirs))

	for i, s := range ours {
		t.Run(s.String(), func(t *testing.T) {
			cipher := theirs[i]
			assert.Equal(t, cipher.ID, uint16(s.ID()))
			assert.Equal(t, cipher.Name, s.String())
			assert.Equal(t, cipherSuiteSupportedVersionIDs(s.ID()), cipher.SupportedVersions)
			assert.False(t, cipher.Insecure, "Expected Insecure")
		})
	}
}

func TestCipherSuiteSupportedVersions(t *testing.T) {
	testCases := []struct {
		name     string
		suite    CipherSuiteID
		expected []protocol.Version
	}{
		{
			name:     "TLS 1.3",
			suite:    TLS_AES_128_GCM_SHA256,
			expected: []protocol.Version{protocol.Version1_3},
		},
		{
			name:     "DTLS 1.2",
			suite:    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			expected: []protocol.Version{protocol.Version1_2},
		},
		{
			name:     "custom suites default to DTLS 1.2",
			suite:    0xffff,
			expected: []protocol.Version{protocol.Version1_2},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expected, cipherSuiteSupportedVersions(testCase.suite))
		})
	}
}

func TestParseCipherSuitesForVersions(t *testing.T) {
	t.Run("default DTLS 1.2", func(t *testing.T) {
		suites, err := parseCipherSuitesForVersions(
			nil,
			nil,
			true,
			false,
			protocol.Version1_2,
			protocol.Version1_2,
		)
		require.NoError(t, err)
		require.NotEmpty(t, suites)

		for _, suite := range suites {
			assert.True(t, cipherSuiteIDSupportsVersion(suite.ID(), protocol.Version1_2))
			assert.False(t, cipherSuiteIDSupportsVersion(suite.ID(), protocol.Version1_3))
		}
	})

	t.Run("default DTLS 1.3", func(t *testing.T) {
		suites, err := parseCipherSuitesForVersions(
			nil,
			nil,
			true,
			false,
			protocol.Version1_3,
			protocol.Version1_3,
		)
		require.NoError(t, err)
		require.Equal(t, []uint16{
			uint16(TLS_AES_128_GCM_SHA256),
			uint16(TLS_AES_256_GCM_SHA384),
			uint16(TLS_CHACHA20_POLY1305_SHA256),
		}, cipherSuiteIDs(suites))
	})

	t.Run("default dual stack", func(t *testing.T) {
		suites, err := parseCipherSuitesForVersions(
			nil,
			nil,
			true,
			false,
			protocol.Version1_2,
			protocol.Version1_3,
		)
		require.NoError(t, err)
		require.Greater(t, len(suites), len(defaultCipherSuites13()))

		assert.Equal(t, uint16(TLS_AES_128_GCM_SHA256), cipherSuiteIDs(suites)[0])
		assert.Contains(t, cipherSuiteIDs(suites), uint16(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256))
	})

	t.Run("selected suites are filtered by version", func(t *testing.T) {
		suites, err := parseCipherSuitesForVersions(
			[]CipherSuiteID{
				TLS_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			nil,
			true,
			false,
			protocol.Version1_2,
			protocol.Version1_2,
		)
		require.NoError(t, err)
		require.Equal(t, []uint16{uint16(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}, cipherSuiteIDs(suites))
	})

	t.Run("selected suite must match version", func(t *testing.T) {
		_, err := parseCipherSuitesForVersions(
			[]CipherSuiteID{TLS_AES_128_GCM_SHA256},
			nil,
			true,
			false,
			protocol.Version1_2,
			protocol.Version1_2,
		)
		require.ErrorIs(t, err, dtlserrors.ErrNoAvailableCertificateCipherSuite)
	})

	t.Run("TLS 1.3 suites are authentication neutral", func(t *testing.T) {
		suites, err := parseCipherSuitesForVersions(
			[]CipherSuiteID{TLS_AES_128_GCM_SHA256},
			nil,
			false,
			true,
			protocol.Version1_3,
			protocol.Version1_3,
		)
		require.NoError(t, err)
		require.Equal(t, []uint16{uint16(TLS_AES_128_GCM_SHA256)}, cipherSuiteIDs(suites))
	})

	t.Run("custom anonymous suites do not satisfy PSK configs", func(t *testing.T) {
		_, err := parseCipherSuitesForVersions(
			[]CipherSuiteID{},
			func() []CipherSuite {
				return []CipherSuite{&testCustomCipherSuite{authenticationType: CipherSuiteAuthenticationTypeAnonymous}}
			},
			false,
			true,
			protocol.Version1_2,
			protocol.Version1_2,
		)
		require.ErrorIs(t, err, dtlserrors.ErrNoAvailablePSKCipherSuite)
	})
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
			client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), []ClientOption{
				WithCustomCipherSuites(cipherFactory),
			}, true)
			resultCh <- result{client, err}
		}()

		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), []ServerOption{
			WithCustomCipherSuites(cipherFactory),
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
