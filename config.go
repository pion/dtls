// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rsa"
	"crypto/tls"
	"net"
	"slices"
	"time"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/logging"
)

const defaultMTU = 1200 // bytes

var defaultCurves = []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384} //nolint:gochecknoglobals

type connConfigValues struct {
	logger                      logging.LeveledLogger
	maximumTransmissionUnit     int
	paddingLengthGenerator      func(uint) uint
	replayProtectionWindow      int
	initialRetransmitInterval   time.Duration
	minVersion                  protocol.Version
	maxVersion                  protocol.Version
	cipherSuites                []dtlsconfig.CipherSuite
	signatureSchemes            []signaturehash.Algorithm
	certificateSignatureSchemes []signaturehash.Algorithm
	ellipticCurves              []elliptic.Curve
	serverName                  string
}

type connConfigCallbacks struct {
	customCipherSuites   func() []dtlsconfig.CipherSuite
	verifyConnection     func(dtlsstate.Active) error
	getCertificate       func(*dtlsconfig.ClientHelloInfo) (*tls.Certificate, error)
	getClientCertificate func(*dtlsconfig.CertificateRequestInfo) (*tls.Certificate, error)
}

type connSessionCallbacks struct {
	getSession func(key []byte) (id, secret []byte, err error)
	setSession func(key, id, secret []byte) error
	delSession func(key []byte) error
}

func newConnConfigValues(config *dtlsConfig) (connConfigValues, error) {
	minVersion, maxVersion := dtlsconfig.NormalizeProtocolVersionRange(config.MinVersion, config.MaxVersion)
	cipherSuites, err := parseCipherSuitesForVersions(
		config.CipherSuites,
		config.customCipherSuites,
		config.includeCertificateSuites(),
		config.psk != nil,
		minVersion,
		maxVersion,
	)
	if err != nil {
		return connConfigValues{}, err
	}

	signatureSchemes, certSignatureSchemes, err := parseConnSignatureSchemes(config)
	if err != nil {
		return connConfigValues{}, err
	}

	return connConfigValues{
		logger:                      newConnLogger(config),
		maximumTransmissionUnit:     effectiveMTU(config.MTU),
		paddingLengthGenerator:      effectivePaddingLengthGenerator(config.PaddingLengthGenerator),
		replayProtectionWindow:      effectiveReplayProtectionWindow(config.ReplayProtectionWindow),
		initialRetransmitInterval:   effectiveFlightInterval(config.FlightInterval),
		minVersion:                  minVersion,
		maxVersion:                  maxVersion,
		cipherSuites:                cipherSuites,
		signatureSchemes:            signatureSchemes,
		certificateSignatureSchemes: certSignatureSchemes,
		ellipticCurves:              effectiveEllipticCurves(config.EllipticCurves),
		serverName:                  effectiveServerName(config.ServerName),
	}, nil
}

func parseConnSignatureSchemes(
	config *dtlsConfig,
) ([]signaturehash.Algorithm, []signaturehash.Algorithm, error) {
	signatureSchemes, err := signaturehash.ParseSignatureSchemes(config.SignatureSchemes, config.InsecureHashes)
	if err != nil {
		return nil, nil, err
	}

	var certSignatureSchemes []signaturehash.Algorithm
	if len(config.CertificateSignatureSchemes) > 0 {
		certSignatureSchemes, err = signaturehash.ParseSignatureSchemes(
			config.CertificateSignatureSchemes,
			config.InsecureHashes,
		)
		if err != nil {
			return nil, nil, err
		}
	}

	return signatureSchemes, certSignatureSchemes, nil
}

func newConnLogger(config *dtlsConfig) logging.LeveledLogger {
	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	return loggerFactory.NewLogger("dtls")
}

func effectiveMTU(mtu int) int {
	if mtu <= 0 {
		return defaultMTU
	}

	return mtu
}

func effectiveReplayProtectionWindow(replayProtectionWindow int) int {
	if replayProtectionWindow <= 0 {
		return defaultReplayProtectionWindow
	}

	return replayProtectionWindow
}

func effectivePaddingLengthGenerator(generator func(uint) uint) func(uint) uint {
	if generator == nil {
		return func(uint) uint { return 0 }
	}

	return generator
}

func effectiveFlightInterval(flightInterval time.Duration) time.Duration {
	if flightInterval <= 0 {
		return initialTickerInterval
	}

	return flightInterval
}

func effectiveServerName(serverName string) string {
	// Do not allow the use of an IP address literal as an SNI value.
	// See RFC 6066, Section 3.
	if net.ParseIP(serverName) != nil {
		return ""
	}

	return serverName
}

func effectiveEllipticCurves(curves []elliptic.Curve) []elliptic.Curve {
	if len(curves) == 0 {
		curves = defaultCurves
	}
	if !fips140.Enabled() {
		return curves
	}

	return filterFIPSCurves(curves)
}

func filterFIPSCurves(curves []elliptic.Curve) []elliptic.Curve {
	filtered := make([]elliptic.Curve, 0, len(curves))
	for _, curve := range curves {
		if curve != elliptic.X25519 && curve != elliptic.X25519MLKEM768 {
			filtered = append(filtered, curve)
		}
	}

	return filtered
}

func newConnConfigCallbacks(config *dtlsConfig) connConfigCallbacks {
	return connConfigCallbacks{
		customCipherSuites:   adaptCustomCipherSuites(config.customCipherSuites),
		verifyConnection:     adaptVerifyConnection(config.verifyConnection),
		getCertificate:       adaptGetCertificate(config.getCertificate),
		getClientCertificate: adaptGetClientCertificate(config.getClientCertificate),
	}
}

func adaptCustomCipherSuites(customCipherSuites func() []CipherSuite) func() []dtlsconfig.CipherSuite {
	if customCipherSuites == nil {
		return nil
	}

	return func() []dtlsconfig.CipherSuite {
		return toConfigCipherSuites(customCipherSuites())
	}
}

func adaptVerifyConnection(verifyConnection func(*State) error) func(dtlsstate.Active) error {
	if verifyConnection == nil {
		return nil
	}

	return func(state dtlsstate.Active) error {
		stateSnapshot, err := generateStateForVerifyConnection(state)
		if err != nil {
			return err
		}

		return verifyConnection(stateSnapshot)
	}
}

func adaptGetCertificate(
	getCertificate func(*ClientHelloInfo) (*tls.Certificate, error),
) func(*dtlsconfig.ClientHelloInfo) (*tls.Certificate, error) {
	if getCertificate == nil {
		return nil
	}

	return func(info *dtlsconfig.ClientHelloInfo) (*tls.Certificate, error) {
		return getCertificate(&ClientHelloInfo{
			ServerName:   info.ServerName,
			CipherSuites: info.CipherSuites,
			RandomBytes:  info.RandomBytes,
		})
	}
}

func adaptGetClientCertificate(
	getClientCertificate func(*CertificateRequestInfo) (*tls.Certificate, error),
) func(*dtlsconfig.CertificateRequestInfo) (*tls.Certificate, error) {
	if getClientCertificate == nil {
		return nil
	}

	return func(info *dtlsconfig.CertificateRequestInfo) (*tls.Certificate, error) {
		signatureSchemes := make([]tls.SignatureScheme, 0, len(info.SignatureSchemes))
		for _, algorithm := range info.SignatureSchemes {
			raw := algorithm.Marshal()
			signatureSchemes = append(signatureSchemes, tls.SignatureScheme(uint16(raw[0])<<8|uint16(raw[1])))
		}

		return getClientCertificate(&CertificateRequestInfo{
			AcceptableCAs:    info.AcceptableCAs,
			SignatureSchemes: signatureSchemes,
		})
	}
}

func newConnSessionCallbacks(sessionStore SessionStore) connSessionCallbacks {
	return connSessionCallbacks{
		getSession: func(key []byte) (id, secret []byte, err error) {
			session, err := sessionStore.Get(key)

			return session.ID, session.Secret, err
		},
		setSession: func(key, id, secret []byte) error {
			return sessionStore.Set(key, Session{ID: id, Secret: secret})
		},
		delSession: func(key []byte) error {
			return sessionStore.Del(key)
		},
	}
}

func newHandshakeConfig(
	config *dtlsConfig,
	configValues connConfigValues,
	callbacks connConfigCallbacks,
	sessions connSessionCallbacks,
	resumeState *dtlsstate.State,
) *dtlsconfig.HandshakeConfig {
	handshakeConfig := &dtlsconfig.HandshakeConfig{
		Log:          configValues.logger,
		InitialEpoch: 0,
		ResumeState:  resumeState,
	}

	setHandshakeConfigCrypto(handshakeConfig, config, configValues)
	setHandshakeConfigIdentity(handshakeConfig, config, configValues, callbacks)
	setHandshakeConfigSession(handshakeConfig, config, sessions)
	setHandshakeConfigTransport(handshakeConfig, config, configValues, callbacks)
	setHandshakeConfigHooks(handshakeConfig, config)

	return handshakeConfig
}

func setHandshakeConfigCrypto(
	handshakeConfig *dtlsconfig.HandshakeConfig,
	config *dtlsConfig,
	configValues connConfigValues,
) {
	handshakeConfig.LocalPSKCallback = config.psk
	handshakeConfig.LocalPSKIdentityHint = config.PSKIdentityHint
	handshakeConfig.LocalCipherSuites = configValues.cipherSuites
	handshakeConfig.LocalSignatureSchemes = configValues.signatureSchemes
	handshakeConfig.LocalCertSignatureSchemes = configValues.certificateSignatureSchemes
	handshakeConfig.ExtendedMasterSecret = dtlsconfig.ExtendedMasterSecretType(config.ExtendedMasterSecret)
	handshakeConfig.LocalCertificates = config.Certificates
	handshakeConfig.RootCAs = config.RootCAs
	handshakeConfig.ClientCAs = config.ClientCAs
	handshakeConfig.EllipticCurves = configValues.ellipticCurves
}

func setHandshakeConfigIdentity(
	handshakeConfig *dtlsconfig.HandshakeConfig,
	config *dtlsConfig,
	configValues connConfigValues,
	callbacks connConfigCallbacks,
) {
	handshakeConfig.ServerName = configValues.serverName
	handshakeConfig.SupportedProtocols = config.SupportedProtocols
	handshakeConfig.ClientAuth = dtlsconfig.ClientAuthType(config.ClientAuth)
	handshakeConfig.InsecureSkipVerify = config.InsecureSkipVerify
	handshakeConfig.VerifyPeerCertificate = config.VerifyPeerCertificate
	handshakeConfig.VerifyConnection = callbacks.verifyConnection
	handshakeConfig.LocalGetCertificate = callbacks.getCertificate
	handshakeConfig.LocalGetClientCertificate = callbacks.getClientCertificate
}

func setHandshakeConfigSession(
	handshakeConfig *dtlsconfig.HandshakeConfig,
	config *dtlsConfig,
	sessions connSessionCallbacks,
) {
	handshakeConfig.HasSessionStore = config.sessionStore != nil
	handshakeConfig.GetSession = sessions.getSession
	handshakeConfig.SetSession = sessions.setSession
	handshakeConfig.DelSession = sessions.delSession
}

func setHandshakeConfigTransport(
	handshakeConfig *dtlsconfig.HandshakeConfig,
	config *dtlsConfig,
	configValues connConfigValues,
	callbacks connConfigCallbacks,
) {
	handshakeConfig.LocalSRTPProtectionProfiles = config.SRTPProtectionProfiles
	handshakeConfig.LocalSRTPMasterKeyIdentifier = config.SRTPMasterKeyIdentifier
	handshakeConfig.CustomCipherSuites = callbacks.customCipherSuites
	handshakeConfig.InitialRetransmitInterval = configValues.initialRetransmitInterval
	handshakeConfig.DisableRetransmitBackoff = config.DisableRetransmitBackoff
	handshakeConfig.KeyLogWriter = config.KeyLogWriter
	handshakeConfig.InsecureSkipHelloVerify = config.InsecureSkipVerifyHello
	handshakeConfig.ConnectionIDGenerator = config.ConnectionIDGenerator
	handshakeConfig.HelloRandomBytesGenerator = config.HelloRandomBytesGenerator
	handshakeConfig.MinVersion = configValues.minVersion
	handshakeConfig.MaxVersion = configValues.maxVersion
}

func setHandshakeConfigHooks(handshakeConfig *dtlsconfig.HandshakeConfig, config *dtlsConfig) {
	handshakeConfig.ClientHelloMessageHook = config.ClientHelloMessageHook
	handshakeConfig.ServerHelloMessageHook = config.ServerHelloMessageHook
	handshakeConfig.CertificateRequestMessageHook = config.CertificateRequestMessageHook
}

func (c *dtlsConfig) includeCertificateSuites() bool {
	return c.psk == nil || len(c.Certificates) > 0 || c.getCertificate != nil || c.getClientCertificate != nil
}

// PSKCallback is called once we have the remote's PSKIdentityHint.
// If the remote provided none it will be nil.
type PSKCallback func([]byte) ([]byte, error)

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

// ClientAuthType enums.
const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

// ExtendedMasterSecretType declares the policy the client and server
// will follow for the Extended Master Secret extension.
type ExtendedMasterSecretType int

// ExtendedMasterSecretType enums.
const (
	RequestExtendedMasterSecret ExtendedMasterSecretType = iota
	RequireExtendedMasterSecret
	DisableExtendedMasterSecret
)

func validateConfig(config *dtlsConfig) error { //nolint:cyclop
	switch {
	case config == nil:
		return dtlserrors.ErrNoConfigProvided
	case config.PSKIdentityHint != nil && config.psk == nil:
		return dtlserrors.ErrIdentityNoPSK
	}

	for _, cert := range config.Certificates {
		if cert.Certificate == nil {
			return dtlserrors.ErrInvalidCertificate
		}
		if cert.PrivateKey != nil {
			signer, ok := cert.PrivateKey.(crypto.Signer)
			if !ok {
				return dtlserrors.ErrInvalidPrivateKey
			}
			switch signer.Public().(type) {
			case ed25519.PublicKey:
			case *ecdsa.PublicKey:
			case *rsa.PublicKey:
			default:
				return dtlserrors.ErrInvalidPrivateKey
			}
		}
	}

	minVersion, maxVersion := dtlsconfig.NormalizeProtocolVersionRange(config.MinVersion, config.MaxVersion)
	if err := validateEllipticCurveVersions(config.EllipticCurves, minVersion, maxVersion); err != nil {
		return err
	}

	_, err := parseCipherSuitesForVersions(
		config.CipherSuites, config.customCipherSuites, config.includeCertificateSuites(), config.psk != nil,
		minVersion, maxVersion,
	)

	return err
}

func validateEllipticCurveVersions(
	curves []elliptic.Curve,
	minVersion, maxVersion protocol.Version,
) error {
	if !slices.Contains(curves, elliptic.X25519MLKEM768) {
		return nil
	}
	if !maxVersion.Equal(protocol.Version1_3) {
		return dtlserrors.ErrUnsupportedEllipticCurveVersion
	}
	if minVersion.Equal(protocol.Version1_3) || hasDTLS12CompatibleCurve(curves) {
		return nil
	}

	return dtlserrors.ErrUnsupportedEllipticCurveVersion
}

func hasDTLS12CompatibleCurve(curves []elliptic.Curve) bool {
	for _, curve := range curves {
		if curve != elliptic.X25519MLKEM768 {
			return true
		}
	}

	return false
}
