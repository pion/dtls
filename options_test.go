// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/tls"
	"syscall"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v4/dpipe"
	"github.com/stretchr/testify/require"
)

func TestClientWithOptionsValidatesOptionValues(t *testing.T) {
	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	_, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(),
		WithExtendedMasterSecret(ExtendedMasterSecretType(-1)))
	require.ErrorIs(t, err, errInvalidExtendedMasterSecretType)
}

func TestServerWithOptionsValidatesOptionValues(t *testing.T) {
	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	// Test invalid client auth type
	_, err := ServerWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(),
		WithClientAuth(ClientAuthType(-1)))
	require.ErrorIs(t, err, errInvalidClientAuthType)
}

func TestWithOptionsCreatesConn(t *testing.T) {
	ca, cb := dpipe.Pipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	client, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(),
		WithCertificates(cert),
		WithInsecureSkipVerify(true),
	)
	require.NoError(t, err)

	server, err := ServerWithOptions(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(),
		WithCertificates(cert),
		WithInsecureSkipVerify(true),
	)
	require.NoError(t, err)

	require.NoError(t, client.Close())
	require.NoError(t, server.Close())
}

// TestEmptySliceOptionsReturnError verifies that functional options return errors
// for empty slices (unlike struct-based Config where empty means default).
func TestEmptySliceOptionsReturnError(t *testing.T) {
	t.Run("EmptyCertificates", func(t *testing.T) {
		_, err := buildClientConfig(WithCertificates())
		require.ErrorIs(t, err, errEmptyCertificates)

		_, err = buildServerConfig(WithCertificates())
		require.ErrorIs(t, err, errEmptyCertificates)
	})

	t.Run("EmptyCipherSuites", func(t *testing.T) {
		_, err := buildClientConfig(WithCipherSuites())
		require.ErrorIs(t, err, errEmptyCipherSuites)

		_, err = buildServerConfig(WithCipherSuites())
		require.ErrorIs(t, err, errEmptyCipherSuites)
	})

	t.Run("EmptySignatureSchemes", func(t *testing.T) {
		_, err := buildClientConfig(WithSignatureSchemes())
		require.ErrorIs(t, err, errEmptySignatureSchemes)

		_, err = buildServerConfig(WithSignatureSchemes())
		require.ErrorIs(t, err, errEmptySignatureSchemes)
	})

	t.Run("EmptySRTPProtectionProfiles", func(t *testing.T) {
		_, err := buildClientConfig(WithSRTPProtectionProfiles())
		require.ErrorIs(t, err, errEmptySRTPProtectionProfiles)

		_, err = buildServerConfig(WithSRTPProtectionProfiles())
		require.ErrorIs(t, err, errEmptySRTPProtectionProfiles)
	})

	t.Run("EmptySupportedProtocols", func(t *testing.T) {
		_, err := buildClientConfig(WithSupportedProtocols())
		require.ErrorIs(t, err, errEmptySupportedProtocols)

		_, err = buildServerConfig(WithSupportedProtocols())
		require.ErrorIs(t, err, errEmptySupportedProtocols)
	})

	t.Run("EmptyEllipticCurves", func(t *testing.T) {
		_, err := buildClientConfig(WithEllipticCurves())
		require.ErrorIs(t, err, errEmptyEllipticCurves)

		_, err = buildServerConfig(WithEllipticCurves())
		require.ErrorIs(t, err, errEmptyEllipticCurves)
	})
}

// TestNilCallbackOptionsReturnError verifies that functional options return errors
// for nil callbacks.
func TestNilCallbackOptionsReturnError(t *testing.T) {
	t.Run("NilCustomCipherSuites", func(t *testing.T) {
		_, err := buildClientConfig(WithCustomCipherSuites(nil))
		require.ErrorIs(t, err, errNilCustomCipherSuites)

		_, err = buildServerConfig(WithCustomCipherSuites(nil))
		require.ErrorIs(t, err, errNilCustomCipherSuites)
	})

	t.Run("NilPSKCallback", func(t *testing.T) {
		_, err := buildClientConfig(WithPSK(nil))
		require.ErrorIs(t, err, errNilPSKCallback)

		_, err = buildServerConfig(WithPSK(nil))
		require.ErrorIs(t, err, errNilPSKCallback)
	})

	t.Run("NilVerifyPeerCertificate", func(t *testing.T) {
		_, err := buildClientConfig(WithVerifyPeerCertificate(nil))
		require.ErrorIs(t, err, errNilVerifyPeerCertificate)

		_, err = buildServerConfig(WithVerifyPeerCertificate(nil))
		require.ErrorIs(t, err, errNilVerifyPeerCertificate)
	})

	t.Run("NilVerifyConnection", func(t *testing.T) {
		_, err := buildClientConfig(WithVerifyConnection(nil))
		require.ErrorIs(t, err, errNilVerifyConnection)

		_, err = buildServerConfig(WithVerifyConnection(nil))
		require.ErrorIs(t, err, errNilVerifyConnection)
	})

	t.Run("NilGetClientCertificate", func(t *testing.T) {
		_, err := buildClientConfig(WithGetClientCertificate(nil))
		require.ErrorIs(t, err, errNilGetClientCertificate)

		_, err = buildServerConfig(WithGetClientCertificate(nil))
		require.ErrorIs(t, err, errNilGetClientCertificate)
	})

	t.Run("NilConnectionIDGenerator", func(t *testing.T) {
		_, err := buildClientConfig(WithConnectionIDGenerator(nil))
		require.ErrorIs(t, err, errNilConnectionIDGenerator)

		_, err = buildServerConfig(WithConnectionIDGenerator(nil))
		require.ErrorIs(t, err, errNilConnectionIDGenerator)
	})

	t.Run("NilPaddingLengthGenerator", func(t *testing.T) {
		_, err := buildClientConfig(WithPaddingLengthGenerator(nil))
		require.ErrorIs(t, err, errNilPaddingLengthGenerator)

		_, err = buildServerConfig(WithPaddingLengthGenerator(nil))
		require.ErrorIs(t, err, errNilPaddingLengthGenerator)
	})

	t.Run("NilHelloRandomBytesGenerator", func(t *testing.T) {
		_, err := buildClientConfig(WithHelloRandomBytesGenerator(nil))
		require.ErrorIs(t, err, errNilHelloRandomBytesGenerator)

		_, err = buildServerConfig(WithHelloRandomBytesGenerator(nil))
		require.ErrorIs(t, err, errNilHelloRandomBytesGenerator)
	})

	t.Run("NilClientHelloMessageHook", func(t *testing.T) {
		_, err := buildClientConfig(WithClientHelloMessageHook(nil))
		require.ErrorIs(t, err, errNilClientHelloMessageHook)

		_, err = buildServerConfig(WithClientHelloMessageHook(nil))
		require.ErrorIs(t, err, errNilClientHelloMessageHook)
	})
}

// TestServerOnlyNilCallbackOptionsReturnError verifies server-only options
// return errors for nil callbacks.
func TestServerOnlyNilCallbackOptionsReturnError(t *testing.T) {
	t.Run("NilGetCertificate", func(t *testing.T) {
		_, err := buildServerConfig(WithGetCertificate(nil))
		require.ErrorIs(t, err, errNilGetCertificate)
	})

	t.Run("NilServerHelloMessageHook", func(t *testing.T) {
		_, err := buildServerConfig(WithServerHelloMessageHook(nil))
		require.ErrorIs(t, err, errNilServerHelloMessageHook)
	})

	t.Run("NilCertificateRequestMessageHook", func(t *testing.T) {
		_, err := buildServerConfig(WithCertificateRequestMessageHook(nil))
		require.ErrorIs(t, err, errNilCertificateRequestMessageHook)
	})

	t.Run("NilOnConnectionAttempt", func(t *testing.T) {
		_, err := buildServerConfig(WithOnConnectionAttempt(nil))
		require.ErrorIs(t, err, errNilOnConnectionAttempt)
	})
}

// TestInvalidNumericOptionsReturnError verifies that invalid numeric values
// return appropriate errors.
func TestInvalidNumericOptionsReturnError(t *testing.T) {
	t.Run("InvalidFlightInterval", func(t *testing.T) {
		_, err := buildClientConfig(WithFlightInterval(0))
		require.ErrorIs(t, err, errInvalidFlightInterval)

		_, err = buildClientConfig(WithFlightInterval(-time.Second))
		require.ErrorIs(t, err, errInvalidFlightInterval)

		_, err = buildServerConfig(WithFlightInterval(0))
		require.ErrorIs(t, err, errInvalidFlightInterval)
	})

	t.Run("InvalidMTU", func(t *testing.T) {
		_, err := buildClientConfig(WithMTU(0))
		require.ErrorIs(t, err, errInvalidMTU)

		_, err = buildClientConfig(WithMTU(-100))
		require.ErrorIs(t, err, errInvalidMTU)

		_, err = buildServerConfig(WithMTU(0))
		require.ErrorIs(t, err, errInvalidMTU)
	})

	t.Run("InvalidReplayProtectionWindow", func(t *testing.T) {
		_, err := buildClientConfig(WithReplayProtectionWindow(-1))
		require.ErrorIs(t, err, errInvalidReplayProtectionWindow)

		_, err = buildServerConfig(WithReplayProtectionWindow(-1))
		require.ErrorIs(t, err, errInvalidReplayProtectionWindow)
	})

	t.Run("InvalidClientAuthType", func(t *testing.T) {
		_, err := buildServerConfig(WithClientAuth(ClientAuthType(-1)))
		require.ErrorIs(t, err, errInvalidClientAuthType)

		_, err = buildServerConfig(WithClientAuth(ClientAuthType(100)))
		require.ErrorIs(t, err, errInvalidClientAuthType)
	})

	t.Run("InvalidExtendedMasterSecretType", func(t *testing.T) {
		_, err := buildClientConfig(WithExtendedMasterSecret(ExtendedMasterSecretType(-1)))
		require.ErrorIs(t, err, errInvalidExtendedMasterSecretType)

		_, err = buildServerConfig(WithExtendedMasterSecret(ExtendedMasterSecretType(100)))
		require.ErrorIs(t, err, errInvalidExtendedMasterSecretType)
	})
}

// TestDefaultsAreApplied verifies that defaults are applied before options.
func TestDefaultsAreApplied(t *testing.T) {
	t.Run("ClientDefaults", func(t *testing.T) {
		config, err := buildClientConfig()
		require.NoError(t, err)

		require.Equal(t, RequestExtendedMasterSecret, config.ExtendedMasterSecret)
		require.Equal(t, time.Second, config.FlightInterval)
		require.Equal(t, defaultMTU, config.MTU)
		require.Equal(t, defaultReplayProtectionWindow, config.ReplayProtectionWindow)
	})

	t.Run("ServerDefaults", func(t *testing.T) {
		config, err := buildServerConfig()
		require.NoError(t, err)

		require.Equal(t, RequestExtendedMasterSecret, config.ExtendedMasterSecret)
		require.Equal(t, time.Second, config.FlightInterval)
		require.Equal(t, defaultMTU, config.MTU)
		require.Equal(t, defaultReplayProtectionWindow, config.ReplayProtectionWindow)
	})
}

// TestOptionsOverrideDefaults verifies that options override defaults.
func TestOptionsOverrideDefaults(t *testing.T) {
	t.Run("ClientOptionsOverrideDefaults", func(t *testing.T) {
		config, err := buildClientConfig(
			WithExtendedMasterSecret(RequireExtendedMasterSecret),
			WithFlightInterval(2*time.Second),
			WithMTU(1500),
			WithReplayProtectionWindow(128),
		)
		require.NoError(t, err)

		require.Equal(t, RequireExtendedMasterSecret, config.ExtendedMasterSecret)
		require.Equal(t, 2*time.Second, config.FlightInterval)
		require.Equal(t, 1500, config.MTU)
		require.Equal(t, 128, config.ReplayProtectionWindow)
	})

	t.Run("ServerOptionsOverrideDefaults", func(t *testing.T) {
		config, err := buildServerConfig(
			WithExtendedMasterSecret(DisableExtendedMasterSecret),
			WithFlightInterval(3*time.Second),
			WithMTU(1400),
			WithReplayProtectionWindow(256),
			WithClientAuth(RequireAndVerifyClientCert),
		)
		require.NoError(t, err)

		require.Equal(t, DisableExtendedMasterSecret, config.ExtendedMasterSecret)
		require.Equal(t, 3*time.Second, config.FlightInterval)
		require.Equal(t, 1400, config.MTU)
		require.Equal(t, 256, config.ReplayProtectionWindow)
		require.Equal(t, RequireAndVerifyClientCert, config.ClientAuth)
	})
}

// TestValidOptionsSucceed verifies that valid options don't return errors.
func TestValidOptionsSucceed(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	t.Run("ClientValidOptions", func(t *testing.T) {
		config, err := buildClientConfig(
			WithCertificates(cert),
			WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			WithSignatureSchemes(tls.ECDSAWithP256AndSHA256),
			WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80),
			WithEllipticCurves(elliptic.P256),
			WithSupportedProtocols("h2", "http/1.1"),
			WithInsecureSkipVerify(true),
			WithServerName("example.com"),
		)
		require.NoError(t, err)

		require.Len(t, config.Certificates, 1)
		require.Len(t, config.CipherSuites, 1)
		require.Len(t, config.SignatureSchemes, 1)
		require.Len(t, config.SRTPProtectionProfiles, 1)
		require.Len(t, config.EllipticCurves, 1)
		require.Len(t, config.SupportedProtocols, 2)
		require.True(t, config.InsecureSkipVerify)
		require.Equal(t, "example.com", config.ServerName)
	})

	controlFunc := func(network, address string, c syscall.RawConn) error {
		return nil
	}

	t.Run("ServerValidOptions", func(t *testing.T) {
		config, err := buildServerConfig(
			WithCertificates(cert),
			WithClientAuth(RequireAndVerifyClientCert),
			WithInsecureSkipVerifyHello(true),
			WithListenConfigControl(controlFunc),
		)
		require.NoError(t, err)

		require.Len(t, config.Certificates, 1)
		require.Equal(t, RequireAndVerifyClientCert, config.ClientAuth)
		require.True(t, config.InsecureSkipVerifyHello)
		require.Equal(t, config.listenConfigControl, controlFunc)
	})
}

// TestOptionImmutability verifies that modifying slices after passing them to options
// does not affect the built config.
func TestOptionImmutability(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	t.Run("Certificates", func(t *testing.T) {
		certs := []tls.Certificate{cert}
		config, err := buildClientConfig(WithCertificates(certs...))
		require.NoError(t, err)

		_ = append(certs, cert)

		require.Len(t, config.Certificates, 1)
	})

	t.Run("CipherSuites", func(t *testing.T) {
		suites := []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
		config, err := buildClientConfig(WithCipherSuites(suites...))
		require.NoError(t, err)

		suites[0] = TLS_PSK_WITH_AES_128_CCM_8

		require.Equal(t, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, config.CipherSuites[0])
	})

	t.Run("SignatureSchemes", func(t *testing.T) {
		schemes := []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}
		config, err := buildClientConfig(WithSignatureSchemes(schemes...))
		require.NoError(t, err)

		schemes[0] = tls.ECDSAWithP384AndSHA384

		require.Equal(t, tls.ECDSAWithP256AndSHA256, config.SignatureSchemes[0])
	})

	t.Run("SRTPProtectionProfiles", func(t *testing.T) {
		profiles := []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80}
		config, err := buildClientConfig(WithSRTPProtectionProfiles(profiles...))
		require.NoError(t, err)

		profiles[0] = SRTP_AES128_CM_HMAC_SHA1_32

		require.Equal(t, SRTP_AES128_CM_HMAC_SHA1_80, config.SRTPProtectionProfiles[0])
	})

	t.Run("SupportedProtocols", func(t *testing.T) {
		protocols := []string{"h2", "http/1.1"}
		config, err := buildClientConfig(WithSupportedProtocols(protocols...))
		require.NoError(t, err)

		protocols[0] = "grpc"

		require.Equal(t, "h2", config.SupportedProtocols[0])
		require.Equal(t, "http/1.1", config.SupportedProtocols[1])
	})

	t.Run("EllipticCurves", func(t *testing.T) {
		curves := []elliptic.Curve{elliptic.P256}
		config, err := buildClientConfig(WithEllipticCurves(curves...))
		require.NoError(t, err)

		curves[0] = elliptic.P384

		require.Equal(t, elliptic.P256, config.EllipticCurves[0])
	})

	t.Run("PSKIdentityHint", func(t *testing.T) {
		hint := []byte("test-hint")
		config, err := buildClientConfig(WithPSKIdentityHint(hint))
		require.NoError(t, err)

		hint[0] = 'X'

		require.Equal(t, []byte("test-hint"), config.PSKIdentityHint)
	})

	t.Run("SRTPMasterKeyIdentifier", func(t *testing.T) {
		identifier := []byte{0x01, 0x02, 0x03}
		config, err := buildClientConfig(WithSRTPMasterKeyIdentifier(identifier))
		require.NoError(t, err)

		identifier[0] = 0xFF

		require.Equal(t, []byte{0x01, 0x02, 0x03}, config.SRTPMasterKeyIdentifier)
	})
}
