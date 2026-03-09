// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha1" //nolint: gosec,gci
	"crypto/sha256"
	"fmt"
	"hash"
	"sync/atomic"

	"github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// TLSEcdheEcdsaWithAes128CbcSha represents a TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA CipherSuite.
type TLSEcdheEcdsaWithAes128CbcSha struct {
	cbc atomic.Value // *cryptoCBC
}

// CertificateType returns what type of certficate this CipherSuite exchanges.
func (c *TLSEcdheEcdsaWithAes128CbcSha) CertificateType() clientcertificate.Type {
	return clientcertificate.ECDSASign
}

// KeyExchangeAlgorithm controls what key exchange algorithm is using during the handshake.
func (c *TLSEcdheEcdsaWithAes128CbcSha) KeyExchangeAlgorithm() KeyExchangeAlgorithm {
	return KeyExchangeAlgorithmEcdhe
}

// ECC uses Elliptic Curve Cryptography.
func (c *TLSEcdheEcdsaWithAes128CbcSha) ECC() bool {
	return true
}

// ID returns the ID of the CipherSuite.
func (c *TLSEcdheEcdsaWithAes128CbcSha) ID() ID {
	return TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
}

func (c *TLSEcdheEcdsaWithAes128CbcSha) String() string {
	return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
}

// HashFunc returns the hashing func for this CipherSuite.
func (c *TLSEcdheEcdsaWithAes128CbcSha) HashFunc() func() hash.Hash {
	return sha256.New
}

// AuthenticationType controls what authentication method is using during the handshake.
func (c *TLSEcdheEcdsaWithAes128CbcSha) AuthenticationType() AuthenticationType {
	return AuthenticationTypeCertificate
}

// IsInitialized returns if the CipherSuite has keying material and can
// encrypt/decrypt packets.
func (c *TLSEcdheEcdsaWithAes128CbcSha) IsInitialized() bool {
	return c.cbc.Load() != nil
}

// Init initializes the internal Cipher with keying material.
func (c *TLSEcdheEcdsaWithAes128CbcSha) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 20
		prfKeyLen = 16
		prfIvLen  = 16
	)

	keys, err := prf.GenerateEncryptionKeys(
		masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, c.HashFunc(),
	)
	if err != nil {
		return err
	}

	var cbc *ciphersuite.CBC
	if isClient {
		cbc, err = ciphersuite.NewCBC(
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			sha1.New, //nolint: gosec
		)
	} else {
		cbc, err = ciphersuite.NewCBC(
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			sha1.New, //nolint: gosec
		)
	}
	c.cbc.Store(cbc)

	return err
}

// Encrypt encrypts a single TLS RecordLayer.
func (c *TLSEcdheEcdsaWithAes128CbcSha) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.cbc.Load().(*ciphersuite.CBC)
	if !ok {
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Encrypt(pkt, raw)
}

// Decrypt decrypts a single TLS RecordLayer.
func (c *TLSEcdheEcdsaWithAes128CbcSha) Decrypt(h recordlayer.Header, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.cbc.Load().(*ciphersuite.CBC)
	if !ok {
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Decrypt(h, raw)
}
