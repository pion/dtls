// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/dsa" //nolint:staticcheck
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"testing"
	"time"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/transport/v4/dpipe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreatesConn(t *testing.T) {
	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	client, err := Client(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(),
		WithCertificates(cert),
		WithInsecureSkipVerify(true),
	)
	require.NoError(t, err)

	server, err := Server(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(),
		WithCertificates(cert),
		WithInsecureSkipVerify(true),
	)
	require.NoError(t, err)

	require.NoError(t, client.Close())
	require.NoError(t, server.Close())
}

func newOptionsClient(t *testing.T, opts ...ClientOption) (*Conn, error) {
	t.Helper()

	ca, cb := dpipe.Pipe()
	t.Cleanup(func() {
		_ = ca.Close()
		_ = cb.Close()
	})

	client, err := Client(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts...)
	if err == nil {
		t.Cleanup(func() {
			_ = client.Close()
		})
	}

	return client, err
}

func newOptionsServer(t *testing.T, opts ...ServerOption) (*Conn, error) {
	t.Helper()

	ca, cb := dpipe.Pipe()
	t.Cleanup(func() {
		_ = ca.Close()
		_ = cb.Close()
	})

	server, err := Server(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts...)
	if err == nil {
		t.Cleanup(func() {
			_ = server.Close()
		})
	}

	return server, err
}

func clientOptionsError(t *testing.T, opts ...ClientOption) error {
	t.Helper()

	client, err := newOptionsClient(t, opts...)
	if client != nil {
		_ = client.Close()
	}

	return err
}

func serverOptionsError(t *testing.T, opts ...ServerOption) error {
	t.Helper()

	server, err := newOptionsServer(t, opts...)
	if server != nil {
		_ = server.Close()
	}

	return err
}

func testSharedOptionErrors(t *testing.T, tests map[string]struct {
	option Option
	want   error
},
) {
	t.Helper()
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, clientOptionsError(t, test.option), test.want)
			require.ErrorIs(t, serverOptionsError(t, test.option), test.want)
		})
	}
}

func newSharedOptionsConn(t *testing.T, server bool, opts ...Option) (*Conn, error) {
	t.Helper()
	if server {
		serverOpts := make([]ServerOption, len(opts))
		for i := range opts {
			serverOpts[i] = opts[i]
		}

		return newOptionsServer(t, serverOpts...)
	}
	clientOpts := make([]ClientOption, len(opts))
	for i := range opts {
		clientOpts[i] = opts[i]
	}

	return newOptionsClient(t, clientOpts...)
}

// TestEmptySliceOptionsReturnError verifies that functional options return errors
// for explicitly empty slices.
func TestEmptySliceOptionsReturnError(t *testing.T) {
	testSharedOptionErrors(t, map[string]struct {
		option Option
		want   error
	}{
		"EmptyCertificates":           {WithCertificates(), dtlserrors.ErrEmptyCertificates},
		"EmptyCipherSuites":           {WithCipherSuites(), dtlserrors.ErrEmptyCipherSuites},
		"EmptySignatureSchemes":       {WithSignatureSchemes(), dtlserrors.ErrEmptySignatureSchemes},
		"EmptySRTPProtectionProfiles": {WithSRTPProtectionProfiles(), dtlserrors.ErrEmptySRTPProtectionProfiles},
		"EmptySupportedProtocols":     {WithSupportedProtocols(), dtlserrors.ErrEmptySupportedProtocols},
		"EmptyEllipticCurves":         {WithEllipticCurves(), dtlserrors.ErrEmptyEllipticCurves},
	})
}

// TestNilCallbackOptionsReturnError verifies that functional options return errors
// for nil callbacks.
func TestNilCallbackOptionsReturnError(t *testing.T) {
	testSharedOptionErrors(t, map[string]struct {
		option Option
		want   error
	}{
		"NilCustomCipherSuites":        {WithCustomCipherSuites(nil), dtlserrors.ErrNilCustomCipherSuites},
		"NilPSKCallback":               {WithPSK(nil), dtlserrors.ErrNilPSKCallback},
		"NilVerifyPeerCertificate":     {WithVerifyPeerCertificate(nil), dtlserrors.ErrNilVerifyPeerCertificate},
		"NilVerifyConnection":          {WithVerifyConnection(nil), dtlserrors.ErrNilVerifyConnection},
		"NilGetClientCertificate":      {WithGetClientCertificate(nil), dtlserrors.ErrNilGetClientCertificate},
		"InvalidConnectionID":          {WithConnectionID(nil, CIDPathMigrationReject), dtlserrors.ErrNilConnectionIDGenerator}, //nolint:lll
		"NilPaddingLengthGenerator":    {WithPaddingLengthGenerator(nil), dtlserrors.ErrNilPaddingLengthGenerator},
		"NilHelloRandomBytesGenerator": {WithHelloRandomBytesGenerator(nil), dtlserrors.ErrNilHelloRandomBytesGenerator},
		"NilClientHelloMessageHook":    {WithClientHelloMessageHook(nil), dtlserrors.ErrNilClientHelloMessageHook},
	})
}

func TestWithConnectionID(t *testing.T) {
	for name, test := range map[string]struct {
		policy    cidPathMigrationPolicy
		enableRRC bool
	}{
		"Reject": {policy: CIDPathMigrationReject},
		"Unsafe": {policy: CIDPathMigrationUnsafe},
		"RRC":    {policy: CIDPathMigrationRRC, enableRRC: true},
	} {
		t.Run(name, func(t *testing.T) {
			expectedCID := []byte{0x01, 0x02}
			cfg, err := buildConfig(WithConnectionID(
				func() []byte { return expectedCID },
				test.policy,
			))
			require.NoError(t, err)
			assert.Equal(t, expectedCID, cfg.ConnectionIDGenerator())
			assert.Equal(t, test.policy, cfg.CIDPathMigrationPolicy)

			values, err := newConnConfigValues(cfg)
			require.NoError(t, err)
			assert.Equal(t, test.policy, values.cidPathMigrationPolicy)
			assert.Equal(t, test.enableRRC, newHandshakeConfig(cfg, values, nil).EnableRRC)
		})
	}

	cfg, err := buildConfig()
	require.NoError(t, err)
	assert.Equal(t, CIDPathMigrationReject, cfg.CIDPathMigrationPolicy)
}

// TestServerOnlyNilCallbackOptionsReturnError verifies server-only options
// return errors for nil callbacks.
func TestServerOnlyNilCallbackOptionsReturnError(t *testing.T) {
	tests := map[string]struct {
		option ServerOption
		want   error
	}{
		"NilGetCertificate":                {WithGetCertificate(nil), dtlserrors.ErrNilGetCertificate},
		"NilServerHelloMessageHook":        {WithServerHelloMessageHook(nil), dtlserrors.ErrNilServerHelloMessageHook},
		"NilCertificateRequestMessageHook": {WithCertificateRequestMessageHook(nil), dtlserrors.ErrNilCertificateRequestMessageHook}, //nolint:lll
		"NilOnConnectionAttempt":           {WithOnConnectionAttempt(nil), dtlserrors.ErrNilOnConnectionAttempt},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, serverOptionsError(t, test.option), test.want)
		})
	}
}

// TestInvalidNumericOptionsReturnError verifies that invalid numeric values
// return appropriate errors.
func TestInvalidNumericOptionsReturnError(t *testing.T) {
	tests := map[string]struct {
		options []Option
		want    error
	}{
		"InvalidFlightInterval":         {[]Option{WithFlightInterval(0), WithFlightInterval(-time.Second)}, dtlserrors.ErrInvalidFlightInterval}, //nolint:lll
		"InvalidMTU":                    {[]Option{WithMTU(0), WithMTU(-100)}, dtlserrors.ErrInvalidMTU},
		"InvalidReplayProtectionWindow": {[]Option{WithReplayProtectionWindow(-1)}, dtlserrors.ErrInvalidReplayProtectionWindow}, //nolint:lll
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			for _, option := range test.options {
				require.ErrorIs(t, clientOptionsError(t, option), test.want)
			}
			require.ErrorIs(t, serverOptionsError(t, test.options[0]), test.want)
		})
	}

	t.Run("InvalidClientAuthType", func(t *testing.T) {
		for _, value := range []ClientAuthType{-1, 100} {
			require.ErrorIs(t, serverOptionsError(t, WithClientAuth(value)), dtlserrors.ErrInvalidClientAuthType)
		}
	})

	t.Run("InvalidExtendedMasterSecretType", func(t *testing.T) {
		require.ErrorIs(t, clientOptionsError(t, WithExtendedMasterSecret(-1)), dtlserrors.ErrInvalidExtendedMasterSecretType)
		require.ErrorIs(t, serverOptionsError(t, WithExtendedMasterSecret(100)), dtlserrors.ErrInvalidExtendedMasterSecretType) //nolint:lll
	})

	t.Run("InvalidVersions", func(t *testing.T) {
		for _, option := range []ClientOption{WithMinVersion(0), WithMaxVersion(0)} {
			require.ErrorIs(t, clientOptionsError(t, option), dtlserrors.ErrUnsupportedProtocolVersion)
		}
	})
}

func TestX25519MLKEM768RequiresDTLS13(t *testing.T) {
	max12 := []Option{WithMaxVersion(protocol.Version1_2), WithEllipticCurves(elliptic.X25519MLKEM768)}
	max13 := []Option{WithMaxVersion(protocol.Version1_3), WithEllipticCurves(elliptic.X25519MLKEM768)}
	exact13 := []Option{WithMinVersion(protocol.Version1_3), WithMaxVersion(protocol.Version1_3), WithEllipticCurves(elliptic.X25519MLKEM768)} //nolint:lll
	for _, test := range []struct {
		name        string
		server      bool
		opts        []Option
		wantErr     error
		checkBounds bool
	}{
		{"DTLS12OnlyClient", false, max12, dtlserrors.ErrUnsupportedEllipticCurveVersion, false},
		{"DTLS12OnlyServer", true, max12, dtlserrors.ErrUnsupportedEllipticCurveVersion, false},
		{"DualStackMLKEMOnlyClient", false, max13, nil, true},
		{"DualStackMLKEMOnlyServer", true, max13, nil, true},
		{"DTLS13OnlyClient", false, exact13, nil, false},
		{"DTLS13OnlyServer", true, exact13, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, err := newSharedOptionsConn(t, test.server, test.opts...)
			require.ErrorIs(t, err, test.wantErr)
			if test.checkBounds {
				require.Equal(t, protocol.Version1_3, conn.handshakeConfig.MinVersion)
				require.Equal(t, protocol.Version1_3, conn.handshakeConfig.MaxVersion)
			}
		})
	}
	t.Run("DualStackWithClassicalFallback", func(t *testing.T) {
		opts := []Option{WithMaxVersion(protocol.Version1_3), WithEllipticCurves(elliptic.X25519MLKEM768, elliptic.X25519)}
		for _, server := range []bool{false, true} {
			_, err := newSharedOptionsConn(t, server, opts...)
			require.NoError(t, err)
		}
	})
}

func TestSelectedCipherSuitesConstrainProtocolVersion(t *testing.T) {
	t.Run("DTLS13SuitesSelectDTLS13", func(t *testing.T) {
		client, err := newOptionsClient(t,
			WithMaxVersion(protocol.Version1_3),
			WithCipherSuites(cryptosuite.TLS_AES_128_GCM_SHA256),
		)
		require.NoError(t, err)
		require.Equal(t, protocol.Version1_3, client.handshakeConfig.MinVersion)
		require.Equal(t, protocol.Version1_3, client.handshakeConfig.MaxVersion)
	})

	t.Run("DTLS12SuitesSelectDTLS12", func(t *testing.T) {
		client, err := newOptionsClient(t,
			WithMaxVersion(protocol.Version1_3),
			WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		)
		require.NoError(t, err)
		require.Equal(t, protocol.Version1_2, client.handshakeConfig.MinVersion)
		require.Equal(t, protocol.Version1_2, client.handshakeConfig.MaxVersion)
	})

	t.Run("DTLS12SuitesAndDTLS13CurvesAreRejected", func(t *testing.T) {
		err := clientOptionsError(t,
			WithMaxVersion(protocol.Version1_3),
			WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		require.ErrorIs(t, err, dtlserrors.ErrNoCommonProtocolVersion)
	})

	t.Run("DTLS12SuitesWithExactDTLS13AreRejected", func(t *testing.T) {
		err := clientOptionsError(t,
			WithMinVersion(protocol.Version1_3),
			WithMaxVersion(protocol.Version1_3),
			WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		)
		require.Error(t, err)
	})
}

// TestDefaultsAreApplied verifies that defaults are applied before options.
func TestDefaultsAreApplied(t *testing.T) {
	t.Run("ClientDefaults", func(t *testing.T) {
		client, err := newOptionsClient(t)
		require.NoError(t, err)

		config := client.handshakeConfig
		require.Equal(t, dtlsconfig.ExtendedMasterSecretType(RequestExtendedMasterSecret), config.ExtendedMasterSecret)
		require.Equal(t, time.Second, config.InitialRetransmitInterval)
		require.Equal(t, defaultMTU, client.maximumTransmissionUnit)
		require.Equal(t, uint(defaultReplayProtectionWindow), client.replayProtectionWindow)
	})

	t.Run("ServerDefaults", func(t *testing.T) {
		server, err := newOptionsServer(t)
		require.NoError(t, err)

		config := server.handshakeConfig
		require.Equal(t, dtlsconfig.ExtendedMasterSecretType(RequestExtendedMasterSecret), config.ExtendedMasterSecret)
		require.Equal(t, time.Second, config.InitialRetransmitInterval)
		require.Equal(t, defaultMTU, server.maximumTransmissionUnit)
		require.Equal(t, uint(defaultReplayProtectionWindow), server.replayProtectionWindow)
	})
}

// TestOptionsOverrideDefaults verifies that options override defaults.
func TestOptionsOverrideDefaults(t *testing.T) {
	t.Run("ClientOptionsOverrideDefaults", func(t *testing.T) {
		client, err := newOptionsClient(t,
			WithExtendedMasterSecret(RequireExtendedMasterSecret),
			WithFlightInterval(2*time.Second),
			WithMTU(1500),
			WithReplayProtectionWindow(128),
		)
		require.NoError(t, err)

		config := client.handshakeConfig
		require.Equal(t, dtlsconfig.ExtendedMasterSecretType(RequireExtendedMasterSecret), config.ExtendedMasterSecret)
		require.Equal(t, 2*time.Second, config.InitialRetransmitInterval)
		require.Equal(t, 1500, client.maximumTransmissionUnit)
		require.Equal(t, uint(128), client.replayProtectionWindow)
	})

	t.Run("ServerOptionsOverrideDefaults", func(t *testing.T) {
		server, err := newOptionsServer(t,
			WithExtendedMasterSecret(DisableExtendedMasterSecret),
			WithFlightInterval(3*time.Second),
			WithMTU(1400),
			WithReplayProtectionWindow(256),
			WithClientAuth(RequireAndVerifyClientCert),
		)
		require.NoError(t, err)

		config := server.handshakeConfig
		require.Equal(t, dtlsconfig.ExtendedMasterSecretType(DisableExtendedMasterSecret), config.ExtendedMasterSecret)
		require.Equal(t, 3*time.Second, config.InitialRetransmitInterval)
		require.Equal(t, 1400, server.maximumTransmissionUnit)
		require.Equal(t, uint(256), server.replayProtectionWindow)
		require.Equal(t, dtlsconfig.ClientAuthType(RequireAndVerifyClientCert), config.ClientAuth)
	})
}

// TestValidOptionsSucceed verifies that valid options don't return errors.
func TestValidOptionsSucceed(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	t.Run("ClientValidOptions", func(t *testing.T) {
		client, err := newOptionsClient(t,
			WithCertificates(cert),
			WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			WithSignatureSchemes(tls.ECDSAWithP256AndSHA256),
			WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80),
			WithEllipticCurves(elliptic.P256),
			WithSupportedProtocols("h2", "http/1.1"),
			WithInsecureSkipVerify(true),
			WithServerName("example.com"),
		)
		require.NoError(t, err)

		config := client.handshakeConfig
		require.Len(t, config.LocalCertificates, 1)
		require.Len(t, config.LocalCipherSuites, 1)
		require.Len(t, config.LocalSignatureSchemes, 1)
		require.Len(t, config.LocalSRTPProtectionProfiles, 1)
		require.Len(t, config.EllipticCurves, 1)
		require.Len(t, config.SupportedProtocols, 2)
		require.True(t, config.InsecureSkipVerify)
		require.Equal(t, "example.com", config.ServerName)
	})

	t.Run("ServerValidOptions", func(t *testing.T) {
		server, err := newOptionsServer(t,
			WithCertificates(cert),
			WithClientAuth(RequireAndVerifyClientCert),
			WithInsecureSkipVerifyHello(true),
		)
		require.NoError(t, err)

		config := server.handshakeConfig
		require.Len(t, config.LocalCertificates, 1)
		require.Equal(t, dtlsconfig.ClientAuthType(RequireAndVerifyClientCert), config.ClientAuth)
		require.True(t, config.InsecureSkipHelloVerify)
	})
}

// TestOptionImmutability verifies that modifying slices after passing them to options
// does not affect the built config.
func TestOptionImmutability(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	certs := []tls.Certificate{cert}
	suites := []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	schemes := []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}
	profiles := []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80}
	protocols := []string{"h2", "http/1.1"}
	curves := []elliptic.Curve{elliptic.P256}
	hint := []byte("test-hint")
	identifier := []byte{0x01, 0x02, 0x03}
	expectedScheme, err := signaturehash.ParseSignatureSchemes(schemes, false)
	require.NoError(t, err)
	tests := map[string]struct {
		opts   []ClientOption
		mutate func()
		got    func(*Conn) any
		want   any
	}{
		"certificates": {
			[]ClientOption{WithCertificates(certs...)},
			func() { _ = append(certs, cert) },
			func(c *Conn) any { return len(c.handshakeConfig.LocalCertificates) }, 1,
		},
		"cipherSuites": {
			[]ClientOption{WithCipherSuites(suites...)},
			func() { suites[0] = cryptosuite.TLS_PSK_WITH_AES_128_CCM_8 },
			func(c *Conn) any { return c.handshakeConfig.LocalCipherSuites[0].ID() }, suites[0],
		},
		"signatureSchemes": {
			[]ClientOption{WithSignatureSchemes(schemes...)},
			func() { schemes[0] = tls.ECDSAWithP384AndSHA384 },
			func(c *Conn) any { return c.handshakeConfig.LocalSignatureSchemes[0] }, expectedScheme[0],
		},
		"srtpProtectionProfiles": {
			[]ClientOption{WithSRTPProtectionProfiles(profiles...)},
			func() { profiles[0] = SRTP_AES128_CM_HMAC_SHA1_32 },
			func(c *Conn) any { return c.handshakeConfig.LocalSRTPProtectionProfiles[0] }, profiles[0],
		},
		"SupportedProtocols": {
			[]ClientOption{WithSupportedProtocols(protocols...)},
			func() { protocols[0] = "grpc" },
			func(c *Conn) any { return c.handshakeConfig.SupportedProtocols },
			[]string{"h2", "http/1.1"},
		},
		"EllipticCurves": {
			[]ClientOption{WithEllipticCurves(curves...)},
			func() { curves[0] = elliptic.P384 },
			func(c *Conn) any { return c.handshakeConfig.EllipticCurves[0] }, curves[0],
		},
		"pskIdentityHint": {
			[]ClientOption{WithPSK(func([]byte) ([]byte, error) { return nil, nil }), WithPSKIdentityHint(hint), WithCipherSuites(cryptosuite.TLS_PSK_WITH_AES_128_CCM_8)}, //nolint:lll
			func() { hint[0] = 'X' }, func(c *Conn) any { return c.handshakeConfig.LocalPSKIdentityHint }, []byte("test-hint"),
		},
		"srtpMasterKeyIdentifier": {
			[]ClientOption{WithSRTPMasterKeyIdentifier(identifier)},
			func() { identifier[0] = 0xFF },
			func(c *Conn) any { return c.handshakeConfig.LocalSRTPMasterKeyIdentifier },
			[]byte{0x01, 0x02, 0x03},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := newOptionsClient(t, test.opts...)
			require.NoError(t, err)
			test.mutate()
			require.Equal(t, test.want, test.got(client))
		})
	}
}

func TestOptionConfiguration(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	dsaPrivateKey := &dsa.PrivateKey{}
	require.NoError(t, dsa.GenerateParameters(&dsaPrivateKey.Parameters, rand.Reader, dsa.L1024N160))
	require.NoError(t, dsa.GenerateKey(dsaPrivateKey, rand.Reader))
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cases := map[string]struct {
		clientOpts []ClientOption
		serverOpts []ServerOption
		wantAnyErr bool
		expErr     error
	}{
		"psk and Certificate, valid cipher suites": {
			serverOpts: []ServerOption{
				WithCipherSuites(cryptosuite.TLS_PSK_WITH_AES_128_CCM_8, cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				WithPSK(func([]byte) ([]byte, error) { return nil, nil }), WithCertificates(cert),
			},
		},
		"psk and Certificate, no psk cipher suite": {
			serverOpts: []ServerOption{
				WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				WithPSK(func([]byte) ([]byte, error) { return nil, nil }), WithCertificates(cert),
			},
			expErr: dtlserrors.ErrNoAvailablePSKCipherSuite,
		},
		"psk and Certificate, no non-psk cipher suite": {
			serverOpts: []ServerOption{
				WithCipherSuites(cryptosuite.TLS_PSK_WITH_AES_128_CCM_8),
				WithPSK(func([]byte) ([]byte, error) { return nil, nil }), WithCertificates(cert),
			},
			expErr: dtlserrors.ErrNoAvailableCertificateCipherSuite,
		},
		"psk identity hint with not psk": {
			serverOpts: []ServerOption{
				WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), WithPSKIdentityHint([]byte{}),
			},
			expErr: dtlserrors.ErrIdentityNoPSK,
		},
		"Invalid private key": {
			clientOpts: []ClientOption{
				WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				WithCertificates(tls.Certificate{Certificate: cert.Certificate, PrivateKey: dsaPrivateKey}),
			},
			expErr: dtlserrors.ErrInvalidPrivateKey,
		},
		"PrivateKey without Certificate": {
			clientOpts: []ClientOption{
				WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				WithCertificates(tls.Certificate{PrivateKey: cert.PrivateKey}),
			},
			expErr: dtlserrors.ErrInvalidCertificate,
		},
		"Invalid cipher suites": {
			clientOpts: []ClientOption{WithCipherSuites(0x0000)},
			wantAnyErr: true,
		},
		"Valid configuration": {
			clientOpts: []ClientOption{
				WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				WithCertificates(cert, tls.Certificate{Certificate: cert.Certificate, PrivateKey: rsaPrivateKey}),
			},
		},
		"Valid configuration with get certificate": {
			serverOpts: []ServerOption{
				WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				WithGetCertificate(func(*ClientHelloInfo) (*tls.Certificate, error) {
					return &tls.Certificate{Certificate: cert.Certificate, PrivateKey: rsaPrivateKey}, nil
				}),
			},
		},
		"Valid configuration with get client certificate": {
			clientOpts: []ClientOption{
				WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				WithGetClientCertificate(func(*CertificateRequestInfo) (*tls.Certificate, error) {
					return &tls.Certificate{Certificate: cert.Certificate, PrivateKey: rsaPrivateKey}, nil
				}),
			},
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			var err error
			if testCase.clientOpts != nil {
				err = clientOptionsError(t, testCase.clientOpts...)
			} else {
				err = serverOptionsError(t, testCase.serverOpts...)
			}
			switch {
			case testCase.wantAnyErr:
				assert.Error(t, err, "option validation expected an error")
			case testCase.expErr == nil:
				assert.NoError(t, err)
			default:
				assert.ErrorIs(t, err, testCase.expErr)
			}
		})
	}
}
