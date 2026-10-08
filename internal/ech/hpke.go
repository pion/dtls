// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build go1.26

package ech

import (
	"bytes"
	"crypto/hpke"
	"slices"

	"github.com/pion/dtls/v4/pkg/protocol/alert"
)

func Available() bool { return true }

func cipherSuite(s CipherSuite) (hpke.KDF, hpke.AEAD, error) {
	if s.AEADID == 0xffff {
		return nil, nil, ErrUnsupported
	}
	kdf, err := hpke.NewKDF(s.KDFID)
	if err != nil {
		return nil, nil, err
	}
	aead, err := hpke.NewAEAD(s.AEADID)

	return kdf, aead, err
}

func NewSender(config Config, s CipherSuite) ([]byte, Sender, error) {
	if !config.Usable() || !slices.Contains(config.SymmetricCipherSuite, s) {
		return nil, nil, ErrUnsupported
	}
	kem, err := hpke.NewKEM(config.KemID)
	if err != nil {
		return nil, nil, err
	}
	pk, err := kem.NewPublicKey(config.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	kdf, aead, err := cipherSuite(s)
	if err != nil {
		return nil, nil, err
	}

	return hpke.NewSender(pk, kdf, aead, config.info())
}

func NewRecipient(config Config, suite CipherSuite, privateKey, enc []byte) (Recipient, error) {
	// Validate local key material before trying peer-controlled parameters.
	kem, err := hpke.NewKEM(config.KemID)
	if err != nil {
		return nil, serverError(alert.InternalError, err)
	}
	key, err := kem.NewPrivateKey(privateKey)
	if err != nil {
		return nil, serverError(alert.InternalError, err)
	}
	if !bytes.Equal(key.PublicKey().Bytes(), config.PublicKey) {
		return nil, serverError(alert.InternalError, ErrInvalid)
	}
	// skip configs that do not advertise the offered suite.
	// https://www.rfc-editor.org/rfc/rfc9849.html#section-7.1
	if !slices.Contains(config.SymmetricCipherSuite, suite) {
		return nil, ErrUnsupported
	}
	kdf, aead, err := cipherSuite(suite)
	if err != nil {
		return nil, serverError(alert.InternalError, err)
	}

	return hpke.NewRecipient(enc, key, kdf, aead, config.info())
}

func (config Config) info() []byte { return append([]byte("tls ech\x00"), config.Raw...) }

// PickConfig selects the first usable configuration and its first supported
// cipher suite, following the server's advertised preference.
// Invalid public keys and unsupported mandatory extensions are skipped.
func PickConfig(configs []Config) (*Config, CipherSuite, error) {
	for i := range configs {
		config := &configs[i]
		if !config.Usable() {
			continue
		}
		kem, err := hpke.NewKEM(config.KemID)
		if err != nil {
			continue
		}
		if _, err := kem.NewPublicKey(config.PublicKey); err != nil {
			continue
		}
		for _, suite := range config.SymmetricCipherSuite {
			_, _, err := cipherSuite(suite)
			if err != nil {
				continue
			}

			return config, suite, nil
		}
	}

	return nil, CipherSuite{}, ErrUnsupported
}
