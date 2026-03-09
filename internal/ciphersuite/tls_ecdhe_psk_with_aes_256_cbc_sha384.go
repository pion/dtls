// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha512"
	"fmt"
	"hash"
	"sync/atomic"

	"github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// TLSEcdhePskWithAes256CbcSha384 implements the TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 CipherSuite.
type TLSEcdhePskWithAes256CbcSha384 struct {
	cbc atomic.Value // *cryptoCBC
}

// NewTLSEcdhePskWithAes256CbcSha384 creates TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 cipher.
func NewTLSEcdhePskWithAes256CbcSha384() *TLSEcdhePskWithAes256CbcSha384 {
	return &TLSEcdhePskWithAes256CbcSha384{}
}

// CertificateType returns what type of certificate this CipherSuite exchanges.
func (c *TLSEcdhePskWithAes256CbcSha384) CertificateType() clientcertificate.Type {
	return clientcertificate.Type(0)
}

// KeyExchangeAlgorithm controls what key exchange algorithm is using during the handshake.
func (c *TLSEcdhePskWithAes256CbcSha384) KeyExchangeAlgorithm() KeyExchangeAlgorithm {
	return KeyExchangeAlgorithmPsk | KeyExchangeAlgorithmEcdhe
}

// ECC uses Elliptic Curve Cryptography.
func (c *TLSEcdhePskWithAes256CbcSha384) ECC() bool {
	return true
}

// ID returns the ID of the CipherSuite.
func (c *TLSEcdhePskWithAes256CbcSha384) ID() ID {
	return TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
}

func (c *TLSEcdhePskWithAes256CbcSha384) String() string {
	return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"
}

// HashFunc returns the hashing func for this CipherSuite.
func (c *TLSEcdhePskWithAes256CbcSha384) HashFunc() func() hash.Hash {
	return sha512.New384
}

// AuthenticationType controls what authentication method is using during the handshake.
func (c *TLSEcdhePskWithAes256CbcSha384) AuthenticationType() AuthenticationType {
	return AuthenticationTypePreSharedKey
}

// IsInitialized returns if the CipherSuite has keying material and can
// encrypt/decrypt packets.
func (c *TLSEcdhePskWithAes256CbcSha384) IsInitialized() bool {
	return c.cbc.Load() != nil
}

// Init initializes the internal Cipher with keying material.
func (c *TLSEcdhePskWithAes256CbcSha384) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 48
		prfKeyLen = 32
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
			c.HashFunc(),
		)
	} else {
		cbc, err = ciphersuite.NewCBC(
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			c.HashFunc(),
		)
	}
	c.cbc.Store(cbc)

	return err
}

// Encrypt encrypts a single TLS RecordLayer.
func (c *TLSEcdhePskWithAes256CbcSha384) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.cbc.Load().(*ciphersuite.CBC)
	if !ok {
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Encrypt(pkt, raw)
}

// Decrypt decrypts a single TLS RecordLayer.
func (c *TLSEcdhePskWithAes256CbcSha384) Decrypt(h recordlayer.Header, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.cbc.Load().(*ciphersuite.CBC)
	if !ok {
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Decrypt(h, raw)
}
