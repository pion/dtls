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

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/logging"
)

const defaultMTU = 1200 // bytes

var defaultCurves = []elliptic.Curve{ //nolint:gochecknoglobals
	elliptic.X25519MLKEM768,
	elliptic.X25519,
	elliptic.P256,
	elliptic.P384,
}

type connConfigValues struct {
	logger                      logging.LeveledLogger
	maximumTransmissionUnit     int
	receiveBufferSize           int
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
	cidPathMigrationPolicy      cidPathMigrationPolicy
}

func newConnConfigValues(config *dtlsConfig) (connConfigValues, error) {
	minVersion, maxVersion, err := effectiveProtocolVersionRange(config)
	if err != nil {
		return connConfigValues{}, err
	}

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
		maximumTransmissionUnit:     config.MTU,
		receiveBufferSize:           config.ReceiveBufferSize,
		paddingLengthGenerator:      config.PaddingLengthGenerator,
		replayProtectionWindow:      effectiveReplayProtectionWindow(config.ReplayProtectionWindow),
		initialRetransmitInterval:   config.FlightInterval,
		minVersion:                  minVersion,
		maxVersion:                  maxVersion,
		cipherSuites:                cipherSuites,
		signatureSchemes:            signatureSchemes,
		certificateSignatureSchemes: certSignatureSchemes,
		ellipticCurves:              effectiveEllipticCurves(config.EllipticCurves),
		serverName:                  effectiveServerName(config.ServerName),
		cidPathMigrationPolicy:      config.CIDPathMigrationPolicy,
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

func effectiveReplayProtectionWindow(replayProtectionWindow int) int {
	if replayProtectionWindow <= 0 {
		return defaultReplayProtectionWindow
	}

	return replayProtectionWindow
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

func newHandshakeConfig(
	config *dtlsConfig,
	configValues connConfigValues,
	resumeState *dtlsstate.State,
) *dtlsconfig.HandshakeConfig {
	handshakeConfig := &dtlsconfig.HandshakeConfig{
		LocalPSKCallback:              config.psk,
		LocalPSKIdentityHint:          config.PSKIdentityHint,
		LocalCipherSuites:             configValues.cipherSuites,
		LocalSignatureSchemes:         configValues.signatureSchemes,
		LocalCertSignatureSchemes:     configValues.certificateSignatureSchemes,
		ExtendedMasterSecret:          dtlsconfig.ExtendedMasterSecretType(config.ExtendedMasterSecret),
		LocalSRTPProtectionProfiles:   config.SRTPProtectionProfiles,
		LocalSRTPMasterKeyIdentifier:  config.SRTPMasterKeyIdentifier,
		ServerName:                    configValues.serverName,
		SupportedProtocols:            config.SupportedProtocols,
		ClientAuth:                    dtlsconfig.ClientAuthType(config.ClientAuth),
		LocalCertificates:             config.Certificates,
		InsecureSkipVerify:            config.InsecureSkipVerify,
		VerifyPeerCertificate:         config.VerifyPeerCertificate,
		VerifyConnection:              adaptVerifyConnection(config.verifyConnection),
		HasSessionStore:               config.sessionStore != nil,
		RootCAs:                       config.RootCAs,
		ClientCAs:                     config.ClientCAs,
		InitialRetransmitInterval:     configValues.initialRetransmitInterval,
		DisableRetransmitBackoff:      config.DisableRetransmitBackoff,
		CustomCipherSuites:            adaptCustomCipherSuites(config.customCipherSuites),
		EllipticCurves:                configValues.ellipticCurves,
		InsecureSkipHelloVerify:       config.InsecureSkipVerifyHello,
		ConnectionIDGenerator:         config.ConnectionIDGenerator,
		EnableRRC:                     config.CIDPathMigrationPolicy == CIDPathMigrationRRC,
		HelloRandomBytesGenerator:     config.HelloRandomBytesGenerator,
		Log:                           configValues.logger,
		KeyLogWriter:                  config.KeyLogWriter,
		LocalGetCertificate:           adaptGetCertificate(config.getCertificate),
		LocalGetClientCertificate:     adaptGetClientCertificate(config.getClientCertificate),
		InitialEpoch:                  0,
		ClientHelloMessageHook:        config.ClientHelloMessageHook,
		ServerHelloMessageHook:        config.ServerHelloMessageHook,
		CertificateRequestMessageHook: config.CertificateRequestMessageHook,
		ResumeState:                   resumeState,
		MinVersion:                    configValues.minVersion,
		MaxVersion:                    configValues.maxVersion,
	}
	if config.sessionStore != nil {
		handshakeConfig.GetSession = func(key []byte) (id, secret []byte, err error) {
			session, err := config.sessionStore.Get(key)

			return session.ID, session.Secret, err
		}
		handshakeConfig.SetSession = func(key, id, secret []byte) error {
			return config.sessionStore.Set(key, Session{ID: id, Secret: secret})
		}
		handshakeConfig.DelSession = config.sessionStore.Del
	}

	return handshakeConfig
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

	minVersion, maxVersion, err := effectiveProtocolVersionRange(config)
	if err != nil {
		return err
	}

	_, err = parseCipherSuitesForVersions(
		config.CipherSuites, config.customCipherSuites, config.includeCertificateSuites(), config.psk != nil,
		minVersion, maxVersion,
	)

	return err
}

// effectiveProtocolVersionRange restricts a configured version range to the
// versions supported by explicitly selected cipher suites and curves. This
// prevents advertising a version for which the local configuration cannot
// complete a handshake.
func effectiveProtocolVersionRange(config *dtlsConfig) (protocol.Version, protocol.Version, error) {
	minVersion, maxVersion := dtlsconfig.NormalizeProtocolVersionRange(config.MinVersion, config.MaxVersion)
	versions := dtlsconfig.SupportedVersionsRange(minVersion, maxVersion)

	if cipherVersions := supportedCipherSuiteVersions(config.CipherSuites, versions); len(cipherVersions) != 0 {
		versions = cipherVersions
	}

	curveVersions := supportedEllipticCurveVersions(
		config.EllipticCurves,
		dtlsconfig.SupportedVersionsRange(minVersion, maxVersion),
	)
	if len(config.EllipticCurves) != 0 && len(curveVersions) == 0 {
		return 0, 0, dtlserrors.ErrUnsupportedEllipticCurveVersion
	}
	versions = intersectSupportedVersions(versions, curveVersions)

	if len(versions) == 0 {
		return 0, 0, dtlserrors.ErrNoCommonProtocolVersion
	}

	return versions[len(versions)-1], versions[0], nil
}

func supportedCipherSuiteVersions(
	suites []CipherSuiteID,
	versions []protocol.Version,
) []protocol.Version {
	if suites == nil {
		return versions
	}

	for _, suite := range suites {
		if ciphersuite.ForID(suite, nil) == nil {
			return versions
		}
	}

	return filterSupportedVersions(versions, func(version protocol.Version) bool {
		return slices.ContainsFunc(suites, func(suite CipherSuiteID) bool {
			return ciphersuite.IDSupportsVersion(suite, version)
		})
	})
}

func supportedEllipticCurveVersions(
	curves []elliptic.Curve,
	versions []protocol.Version,
) []protocol.Version {
	if len(curves) == 0 {
		return versions
	}

	return filterSupportedVersions(versions, func(version protocol.Version) bool {
		return slices.ContainsFunc(curves, func(curve elliptic.Curve) bool {
			return curve != elliptic.X25519MLKEM768 || version == protocol.Version1_3
		})
	})
}

func filterSupportedVersions(
	versions []protocol.Version,
	supports func(protocol.Version) bool,
) []protocol.Version {
	filtered := make([]protocol.Version, 0, len(versions))
	for _, version := range versions {
		if supports(version) {
			filtered = append(filtered, version)
		}
	}

	return filtered
}

func intersectSupportedVersions(
	left, right []protocol.Version,
) []protocol.Version {
	return filterSupportedVersions(left, func(version protocol.Version) bool {
		return slices.Contains(right, version)
	})
}
