// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
)

const keyLogLabelTLS12 = "CLIENT_RANDOM"

func (c *dtlsConfig) includeCertificateSuites() bool {
	return c.psk == nil || len(c.certificates) > 0 || c.getCertificate != nil || c.getClientCertificate != nil
}

const defaultMTU = 1200 // bytes

var defaultCurves = []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384} //nolint:gochecknoglobals

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
	case config.pskIdentityHint != nil && config.psk == nil:
		return dtlserrors.ErrIdentityNoPSK
	}

	for _, cert := range config.certificates {
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

	minVersion, maxVersion := normalizeProtocolVersionRange(config.minVersion, config.maxVersion)
	_, err := parseCipherSuitesForVersions(
		config.cipherSuites, config.customCipherSuites, config.includeCertificateSuites(), config.psk != nil,
		minVersion, maxVersion,
	)

	return err
}
