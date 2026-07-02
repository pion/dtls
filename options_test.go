// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/tls"
	"net"
	"syscall"
	"testing"
	"time"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
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
	require.ErrorIs(t, err, dtlserrors.ErrInvalidExtendedMasterSecretType)
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
	require.ErrorIs(t, err, dtlserrors.ErrInvalidClientAuthType)
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

func newOptionsClient(t *testing.T, opts ...ClientOption) (*Conn, error) {
	t.Helper()

	ca, cb := dpipe.Pipe()
	t.Cleanup(func() {
		_ = ca.Close()
		_ = cb.Close()
	})

	client, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts...)
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

	server, err := ServerWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), opts...)
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

// TestEmptySliceOptionsReturnError verifies that functional options return errors
// for explicitly empty slices.
func TestEmptySliceOptionsReturnError(t *testing.T) {
	t.Run("EmptyCertificates", func(t *testing.T) {
		err := clientOptionsError(t, WithCertificates())
		require.ErrorIs(t, err, dtlserrors.ErrEmptyCertificates)

		err = serverOptionsError(t, WithCertificates())
		require.ErrorIs(t, err, dtlserrors.ErrEmptyCertificates)
	})

	t.Run("EmptyCipherSuites", func(t *testing.T) {
		err := clientOptionsError(t, WithCipherSuites())
		require.ErrorIs(t, err, dtlserrors.ErrEmptyCipherSuites)

		err = serverOptionsError(t, WithCipherSuites())
		require.ErrorIs(t, err, dtlserrors.ErrEmptyCipherSuites)
	})

	t.Run("EmptySignatureSchemes", func(t *testing.T) {
		err := clientOptionsError(t, WithSignatureSchemes())
		require.ErrorIs(t, err, dtlserrors.ErrEmptySignatureSchemes)

		err = serverOptionsError(t, WithSignatureSchemes())
		require.ErrorIs(t, err, dtlserrors.ErrEmptySignatureSchemes)
	})

	t.Run("EmptySRTPProtectionProfiles", func(t *testing.T) {
		err := clientOptionsError(t, WithSRTPProtectionProfiles())
		require.ErrorIs(t, err, dtlserrors.ErrEmptySRTPProtectionProfiles)

		err = serverOptionsError(t, WithSRTPProtectionProfiles())
		require.ErrorIs(t, err, dtlserrors.ErrEmptySRTPProtectionProfiles)
	})

	t.Run("EmptySupportedProtocols", func(t *testing.T) {
		err := clientOptionsError(t, WithSupportedProtocols())
		require.ErrorIs(t, err, dtlserrors.ErrEmptySupportedProtocols)

		err = serverOptionsError(t, WithSupportedProtocols())
		require.ErrorIs(t, err, dtlserrors.ErrEmptySupportedProtocols)
	})

	t.Run("EmptyEllipticCurves", func(t *testing.T) {
		err := clientOptionsError(t, WithEllipticCurves())
		require.ErrorIs(t, err, dtlserrors.ErrEmptyEllipticCurves)

		err = serverOptionsError(t, WithEllipticCurves())
		require.ErrorIs(t, err, dtlserrors.ErrEmptyEllipticCurves)
	})
}

// TestNilCallbackOptionsReturnError verifies that functional options return errors
// for nil callbacks.
func TestNilCallbackOptionsReturnError(t *testing.T) {
	t.Run("NilCustomCipherSuites", func(t *testing.T) {
		err := clientOptionsError(t, WithCustomCipherSuites(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilCustomCipherSuites)

		err = serverOptionsError(t, WithCustomCipherSuites(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilCustomCipherSuites)
	})

	t.Run("NilPSKCallback", func(t *testing.T) {
		err := clientOptionsError(t, WithPSK(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilPSKCallback)

		err = serverOptionsError(t, WithPSK(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilPSKCallback)
	})

	t.Run("NilVerifyPeerCertificate", func(t *testing.T) {
		err := clientOptionsError(t, WithVerifyPeerCertificate(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilVerifyPeerCertificate)

		err = serverOptionsError(t, WithVerifyPeerCertificate(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilVerifyPeerCertificate)
	})

	t.Run("NilVerifyConnection", func(t *testing.T) {
		err := clientOptionsError(t, WithVerifyConnection(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilVerifyConnection)

		err = serverOptionsError(t, WithVerifyConnection(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilVerifyConnection)
	})

	t.Run("NilGetClientCertificate", func(t *testing.T) {
		err := clientOptionsError(t, WithGetClientCertificate(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilGetClientCertificate)

		err = serverOptionsError(t, WithGetClientCertificate(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilGetClientCertificate)
	})

	t.Run("NilConnectionIDGenerator", func(t *testing.T) {
		err := clientOptionsError(t, WithConnectionIDGenerator(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilConnectionIDGenerator)

		err = serverOptionsError(t, WithConnectionIDGenerator(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilConnectionIDGenerator)
	})

	t.Run("NilPaddingLengthGenerator", func(t *testing.T) {
		err := clientOptionsError(t, WithPaddingLengthGenerator(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilPaddingLengthGenerator)

		err = serverOptionsError(t, WithPaddingLengthGenerator(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilPaddingLengthGenerator)
	})

	t.Run("NilHelloRandomBytesGenerator", func(t *testing.T) {
		err := clientOptionsError(t, WithHelloRandomBytesGenerator(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilHelloRandomBytesGenerator)

		err = serverOptionsError(t, WithHelloRandomBytesGenerator(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilHelloRandomBytesGenerator)
	})

	t.Run("NilClientHelloMessageHook", func(t *testing.T) {
		err := clientOptionsError(t, WithClientHelloMessageHook(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilClientHelloMessageHook)

		err = serverOptionsError(t, WithClientHelloMessageHook(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilClientHelloMessageHook)
	})
}

// TestServerOnlyNilCallbackOptionsReturnError verifies server-only options
// return errors for nil callbacks.
func TestServerOnlyNilCallbackOptionsReturnError(t *testing.T) {
	t.Run("NilGetCertificate", func(t *testing.T) {
		err := serverOptionsError(t, WithGetCertificate(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilGetCertificate)
	})

	t.Run("NilServerHelloMessageHook", func(t *testing.T) {
		err := serverOptionsError(t, WithServerHelloMessageHook(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilServerHelloMessageHook)
	})

	t.Run("NilCertificateRequestMessageHook", func(t *testing.T) {
		err := serverOptionsError(t, WithCertificateRequestMessageHook(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilCertificateRequestMessageHook)
	})

	t.Run("NilOnConnectionAttempt", func(t *testing.T) {
		err := serverOptionsError(t, WithOnConnectionAttempt(nil))
		require.ErrorIs(t, err, dtlserrors.ErrNilOnConnectionAttempt)
	})
}

// TestInvalidNumericOptionsReturnError verifies that invalid numeric values
// return appropriate errors.
func TestInvalidNumericOptionsReturnError(t *testing.T) {
	t.Run("InvalidFlightInterval", func(t *testing.T) {
		err := clientOptionsError(t, WithFlightInterval(0))
		require.ErrorIs(t, err, dtlserrors.ErrInvalidFlightInterval)

		err = clientOptionsError(t, WithFlightInterval(-time.Second))
		require.ErrorIs(t, err, dtlserrors.ErrInvalidFlightInterval)

		err = serverOptionsError(t, WithFlightInterval(0))
		require.ErrorIs(t, err, dtlserrors.ErrInvalidFlightInterval)
	})

	t.Run("InvalidMTU", func(t *testing.T) {
		err := clientOptionsError(t, WithMTU(0))
		require.ErrorIs(t, err, dtlserrors.ErrInvalidMTU)

		err = clientOptionsError(t, WithMTU(-100))
		require.ErrorIs(t, err, dtlserrors.ErrInvalidMTU)

		err = serverOptionsError(t, WithMTU(0))
		require.ErrorIs(t, err, dtlserrors.ErrInvalidMTU)
	})

	t.Run("InvalidReplayProtectionWindow", func(t *testing.T) {
		err := clientOptionsError(t, WithReplayProtectionWindow(-1))
		require.ErrorIs(t, err, dtlserrors.ErrInvalidReplayProtectionWindow)

		err = serverOptionsError(t, WithReplayProtectionWindow(-1))
		require.ErrorIs(t, err, dtlserrors.ErrInvalidReplayProtectionWindow)
	})

	t.Run("InvalidClientAuthType", func(t *testing.T) {
		err := serverOptionsError(t, WithClientAuth(ClientAuthType(-1)))
		require.ErrorIs(t, err, dtlserrors.ErrInvalidClientAuthType)

		err = serverOptionsError(t, WithClientAuth(ClientAuthType(100)))
		require.ErrorIs(t, err, dtlserrors.ErrInvalidClientAuthType)
	})

	t.Run("InvalidExtendedMasterSecretType", func(t *testing.T) {
		err := clientOptionsError(t, WithExtendedMasterSecret(ExtendedMasterSecretType(-1)))
		require.ErrorIs(t, err, dtlserrors.ErrInvalidExtendedMasterSecretType)

		err = serverOptionsError(t, WithExtendedMasterSecret(ExtendedMasterSecretType(100)))
		require.ErrorIs(t, err, dtlserrors.ErrInvalidExtendedMasterSecretType)
	})

	t.Run("InvalidVersions", func(t *testing.T) {
		err := clientOptionsError(t, WithMinVersion(protocol.Version{}))
		require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)

		err = clientOptionsError(t, WithMaxVersion(protocol.Version{}))
		require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
	})
}

func TestX25519MLKEM768RequiresDTLS13(t *testing.T) {
	t.Run("DTLS12OnlyClient", func(t *testing.T) {
		err := clientOptionsError(t,
			WithMaxVersion(protocol.Version1_2),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		require.ErrorIs(t, err, dtlserrors.ErrUnsupportedEllipticCurveVersion)
	})

	t.Run("DTLS12OnlyServer", func(t *testing.T) {
		err := serverOptionsError(t,
			WithMaxVersion(protocol.Version1_2),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		require.ErrorIs(t, err, dtlserrors.ErrUnsupportedEllipticCurveVersion)
	})

	t.Run("DualStackMLKEMOnlyClient", func(t *testing.T) {
		err := clientOptionsError(t,
			WithMaxVersion(protocol.Version1_3),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		require.ErrorIs(t, err, dtlserrors.ErrUnsupportedEllipticCurveVersion)
	})

	t.Run("DualStackMLKEMOnlyServer", func(t *testing.T) {
		err := serverOptionsError(t,
			WithMaxVersion(protocol.Version1_3),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		require.ErrorIs(t, err, dtlserrors.ErrUnsupportedEllipticCurveVersion)
	})

	t.Run("DualStackWithClassicalFallback", func(t *testing.T) {
		_, err := newOptionsClient(t,
			WithMaxVersion(protocol.Version1_3),
			WithEllipticCurves(elliptic.X25519MLKEM768, elliptic.X25519),
		)
		require.NoError(t, err)

		_, err = newOptionsServer(t,
			WithMaxVersion(protocol.Version1_3),
			WithEllipticCurves(elliptic.X25519MLKEM768, elliptic.X25519),
		)
		require.NoError(t, err)
	})

	t.Run("DTLS13OnlyClient", func(t *testing.T) {
		_, err := newOptionsClient(t,
			WithMinVersion(protocol.Version1_3),
			WithMaxVersion(protocol.Version1_3),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		require.NoError(t, err)
	})

	t.Run("DTLS13OnlyServer", func(t *testing.T) {
		_, err := newOptionsServer(t,
			WithMinVersion(protocol.Version1_3),
			WithMaxVersion(protocol.Version1_3),
			WithEllipticCurves(elliptic.X25519MLKEM768),
		)
		require.NoError(t, err)
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
			WithCipherSuites(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
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
			WithListenConfig(net.ListenConfig{
				Control: func(network, address string, c syscall.RawConn) error {
					return nil
				},
			}),
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

	t.Run("certificates", func(t *testing.T) {
		certs := []tls.Certificate{cert}
		client, err := newOptionsClient(t, WithCertificates(certs...))
		require.NoError(t, err)

		_ = append(certs, cert)

		require.Len(t, client.handshakeConfig.LocalCertificates, 1)
	})

	t.Run("cipherSuites", func(t *testing.T) {
		suites := []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
		client, err := newOptionsClient(t, WithCipherSuites(suites...))
		require.NoError(t, err)

		suites[0] = TLS_PSK_WITH_AES_128_CCM_8

		require.Equal(t, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, client.handshakeConfig.LocalCipherSuites[0].ID())
	})

	t.Run("signatureSchemes", func(t *testing.T) {
		schemes := []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}
		client, err := newOptionsClient(t, WithSignatureSchemes(schemes...))
		require.NoError(t, err)

		schemes[0] = tls.ECDSAWithP384AndSHA384

		expected, err := signaturehash.ParseSignatureSchemes([]tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}, false)
		require.NoError(t, err)
		require.Equal(t, expected[0], client.handshakeConfig.LocalSignatureSchemes[0])
	})

	t.Run("srtpProtectionProfiles", func(t *testing.T) {
		profiles := []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80}
		client, err := newOptionsClient(t, WithSRTPProtectionProfiles(profiles...))
		require.NoError(t, err)

		profiles[0] = SRTP_AES128_CM_HMAC_SHA1_32

		require.Equal(t, SRTP_AES128_CM_HMAC_SHA1_80, client.handshakeConfig.LocalSRTPProtectionProfiles[0])
	})

	t.Run("SupportedProtocols", func(t *testing.T) {
		protocols := []string{"h2", "http/1.1"} //nolint:goconst
		client, err := newOptionsClient(t, WithSupportedProtocols(protocols...))
		require.NoError(t, err)

		protocols[0] = "grpc"

		require.Equal(t, "h2", client.handshakeConfig.SupportedProtocols[0])
		require.Equal(t, "http/1.1", client.handshakeConfig.SupportedProtocols[1])
	})

	t.Run("EllipticCurves", func(t *testing.T) {
		curves := []elliptic.Curve{elliptic.P256}
		client, err := newOptionsClient(t, WithEllipticCurves(curves...))
		require.NoError(t, err)

		curves[0] = elliptic.P384

		require.Equal(t, elliptic.P256, client.handshakeConfig.EllipticCurves[0])
	})

	t.Run("pskIdentityHint", func(t *testing.T) {
		hint := []byte("test-hint")
		client, err := newOptionsClient(t,
			WithPSK(func([]byte) ([]byte, error) { return nil, nil }),
			WithPSKIdentityHint(hint),
			WithCipherSuites(TLS_PSK_WITH_AES_128_CCM_8),
		)
		require.NoError(t, err)

		hint[0] = 'X'

		require.Equal(t, []byte("test-hint"), client.handshakeConfig.LocalPSKIdentityHint)
	})

	t.Run("srtpMasterKeyIdentifier", func(t *testing.T) {
		identifier := []byte{0x01, 0x02, 0x03}
		client, err := newOptionsClient(t, WithSRTPMasterKeyIdentifier(identifier))
		require.NoError(t, err)

		identifier[0] = 0xFF

		require.Equal(t, []byte{0x01, 0x02, 0x03}, client.handshakeConfig.LocalSRTPMasterKeyIdentifier)
	})
}
