package dtls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
)

func validateConfig(config *Config) error {
	switch {
	case config == nil:
		return errNoConfigProvided
	case config.Certificate != nil && config.PSK != nil:
		return errPSKAndCertificate
	case config.PSKIdentityHint != nil && config.PSK == nil:
		return errIdentityNoPSK
	}

	if config.PrivateKey != nil {
		switch config.PrivateKey.(type) {
		case ed25519.PrivateKey:
		case *ecdsa.PrivateKey:
		default:
			return errInvalidPrivateKey
		}
	}

	_, err := parseCipherSuites(config.CipherSuites, config.PSK == nil, config.PSK != nil)
	if err != nil {
		return err
	}

	return nil
}
