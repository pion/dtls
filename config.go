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
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
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

	cipherSuites, err := selectCipherSuites(
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

	_, err = selectCipherSuites(
		config.CipherSuites, config.customCipherSuites, config.includeCertificateSuites(), config.psk != nil,
		minVersion, maxVersion,
	)

	return err
}

func defaultCipherSuitesForVersion(version protocol.Version) []cryptosuite.Suite {
	var ids []cryptosuite.ID
	switch version {
	case protocol.Version1_3:
		ids = []cryptosuite.ID{
			cryptosuite.TLS_AES_128_GCM_SHA256,
			cryptosuite.TLS_AES_256_GCM_SHA384,
			cryptosuite.TLS_CHACHA20_POLY1305_SHA256,
		}
	case protocol.Version1_2:
		ids = []cryptosuite.ID{
			cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			cryptosuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			cryptosuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			cryptosuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			cryptosuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}
	case protocol.Version1_0:
		return nil
	}

	suites := make([]cryptosuite.Suite, len(ids))
	for i, id := range ids {
		suites[i] = ciphersuite.ForID(id)
	}

	return suites
}

func filterCipherSuitesForVersion(
	cipherSuites []cryptosuite.Suite,
	version protocol.Version,
) []cryptosuite.Suite {
	return slices.DeleteFunc(slices.Clone(cipherSuites), func(suite cryptosuite.Suite) bool {
		return !suite.Capabilities().SupportsVersion(version)
	})
}

//nolint:cyclop,gocognit
func selectCipherSuites(
	selectedIDs []cryptosuite.ID,
	customCipherSuites func() []cryptosuite.Suite,
	includeCertificateSuites, includePSKSuites bool,
	minVersion, maxVersion protocol.Version,
) ([]cryptosuite.Suite, error) {
	customByID := make(map[cryptosuite.ID]cryptosuite.Suite)
	var custom []cryptosuite.Suite
	if customCipherSuites != nil {
		custom = customCipherSuites()
		for _, suite := range custom {
			if suite == nil || ciphersuite.ForID(suite.ID()) != nil || customByID[suite.ID()] != nil {
				return nil, dtlserrors.ErrInvalidCipherSuite
			}
			if err := validateCipherSuite(suite); err != nil {
				return nil, err
			}
			customByID[suite.ID()] = suite
		}
	}

	var cipherSuites []cryptosuite.Suite
	if selectedIDs != nil {
		cipherSuites = make([]cryptosuite.Suite, 0, len(selectedIDs))
		for _, id := range selectedIDs {
			suite := customByID[id]
			if suite == nil {
				suite = ciphersuite.ForID(id)
			}
			if suite == nil {
				return nil, &invalidCipherSuiteError{id}
			}
			if err := validateCipherSuite(suite); err != nil {
				return nil, err
			}
			cipherSuites = append(cipherSuites, suite)
		}
	} else {
		for _, version := range dtlsconfig.SupportedVersionsRange(minVersion, maxVersion) {
			cipherSuites = append(cipherSuites, defaultCipherSuitesForVersion(version)...)
		}
	}

	// Without an explicit ID list, external suites are enabled ahead of the
	// defaults. With an explicit list, the provider is only a registry.
	if selectedIDs == nil && len(custom) > 0 {
		cipherSuites = append(append(make([]cryptosuite.Suite, 0, len(custom)+len(cipherSuites)), custom...), cipherSuites...)
	}

	versions := dtlsconfig.SupportedVersionsRange(minVersion, maxVersion)
	cipherSuites = slices.DeleteFunc(cipherSuites, func(suite cryptosuite.Suite) bool {
		return !slices.ContainsFunc(versions, suite.Capabilities().SupportsVersion)
	})

	var foundCertificateSuite, foundPSKSuite, foundTrafficSuite bool
	i := 0
	for _, suite := range cipherSuites {
		if suite.Capabilities().SupportsVersion(protocol.Version1_3) {
			foundTrafficSuite = true
			cipherSuites[i] = suite
			i++

			continue
		}
		switch {
		case includeCertificateSuites && suite.AuthenticationType() == cryptosuite.AuthenticationTypeCertificate:
			foundCertificateSuite = true
		case includePSKSuites && suite.AuthenticationType() == cryptosuite.AuthenticationTypePreSharedKey:
			foundPSKSuite = true
		case suite.AuthenticationType() == cryptosuite.AuthenticationTypeAnonymous:
		default:
			continue
		}
		cipherSuites[i] = suite
		i++
	}

	switch {
	case includeCertificateSuites && !foundCertificateSuite && !foundTrafficSuite:
		return nil, dtlserrors.ErrNoAvailableCertificateCipherSuite
	case includePSKSuites && !foundPSKSuite && !foundTrafficSuite:
		return nil, dtlserrors.ErrNoAvailablePSKCipherSuite
	case i == 0:
		return nil, dtlserrors.ErrNoAvailableCipherSuites
	}

	return cipherSuites[:i], nil
}

func validateCipherSuite(suite cryptosuite.Suite) error { //nolint:cyclop
	if suite == nil || suite.ID() == 0 {
		return dtlserrors.ErrInvalidCipherSuite
	}
	hashFunc := suite.HashFunc()
	if hashFunc == nil {
		return dtlserrors.ErrInvalidCipherSuite
	}
	hashInstance := hashFunc()
	if hashInstance == nil || hashInstance.Size() <= 0 || hashInstance.BlockSize() <= 0 {
		return dtlserrors.ErrInvalidCipherSuite
	}

	switch suite.Capabilities().Version() {
	case protocol.Version1_2:
		if _, ok := suite.(cryptosuite.ConnectionSuite); !ok {
			return dtlserrors.ErrInvalidCipherSuite
		}
	case protocol.Version1_3:
		if _, ok := suite.(cryptosuite.TrafficSuite); !ok {
			return dtlserrors.ErrInvalidCipherSuite
		}
	default:
		return dtlserrors.ErrInvalidCipherSuite
	}

	return nil
}

func filterCipherSuitesForCertificate(
	cert *tls.Certificate,
	cipherSuites []cryptosuite.Suite,
) []cryptosuite.Suite {
	if cert == nil || cert.PrivateKey == nil {
		return cipherSuites
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return cipherSuites
	}

	var certType clientcertificate.Type
	switch signer.Public().(type) {
	case ed25519.PublicKey, *ecdsa.PublicKey:
		certType = clientcertificate.ECDSASign
	case *rsa.PublicKey:
		certType = clientcertificate.RSASign
	}

	return slices.DeleteFunc(slices.Clone(cipherSuites), func(suite cryptosuite.Suite) bool {
		return !suite.Capabilities().SupportsVersion(protocol.Version1_3) &&
			suite.AuthenticationType() == cryptosuite.AuthenticationTypeCertificate && certType != suite.CertificateType()
	})
}

// effectiveProtocolVersionRange restricts a configured version range to the
// versions supported by explicitly selected cipher suites and curves. This
// prevents advertising a version for which the local configuration cannot
// complete a handshake.
func effectiveProtocolVersionRange(config *dtlsConfig) (protocol.Version, protocol.Version, error) {
	minVersion, maxVersion := dtlsconfig.NormalizeProtocolVersionRange(config.MinVersion, config.MaxVersion)
	versions := dtlsconfig.SupportedVersionsRange(minVersion, maxVersion)

	if cipherVersions := supportedCipherSuiteVersions(
		config.CipherSuites,
		config.customCipherSuites,
		versions,
	); len(cipherVersions) != 0 {
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
	suites []cryptosuite.ID,
	customCipherSuites func() []cryptosuite.Suite,
	versions []protocol.Version,
) []protocol.Version {
	if suites == nil {
		return versions
	}

	customByID := make(map[cryptosuite.ID]cryptosuite.Suite)
	if customCipherSuites != nil {
		for _, suite := range customCipherSuites() {
			if suite != nil {
				customByID[suite.ID()] = suite
			}
		}
	}
	descriptors := make([]cryptosuite.Suite, 0, len(suites))
	for _, id := range suites {
		suite := customByID[id]
		if suite == nil {
			suite = ciphersuite.ForID(id)
		}
		if suite == nil {
			return versions
		}
		descriptors = append(descriptors, suite)
	}

	return filterSupportedVersions(versions, func(version protocol.Version) bool {
		return slices.ContainsFunc(descriptors, func(suite cryptosuite.Suite) bool {
			return suite.Capabilities().SupportsVersion(version)
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
