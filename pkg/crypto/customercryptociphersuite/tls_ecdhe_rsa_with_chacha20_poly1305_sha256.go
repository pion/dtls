package customercryptociphersuite

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"sync/atomic"

	internal_ciphersuite "github.com/pion/dtls/v3/internal/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

type TLSEcdheRsaWithChaCha20Poly1305Sha256 struct {
	chacha atomic.Value
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) CertificateType() clientcertificate.Type {
	return clientcertificate.ECDSASign
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) KeyExchangeAlgorithm() internal_ciphersuite.KeyExchangeAlgorithm {
	return internal_ciphersuite.KeyExchangeAlgorithmEcdhe
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) ECC() bool {
	return true
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) ID() internal_ciphersuite.ID {

	return internal_ciphersuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) String() string {
	return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) HashFunc() func() hash.Hash {
	return sha256.New
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) AuthenticationType() internal_ciphersuite.AuthenticationType {
	return internal_ciphersuite.AuthenticationTypeCertificate
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) IsInitialized() bool {
	return c.chacha.Load() != nil
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) init(masterSecret, clientRandom, serverRandom []byte, isClient bool,
	rfMacLen, prfKeyLen, prfIvLen int, hashFunc func() hash.Hash) error {

	if masterSecret == nil {
		return errors.New("masterSecret is nil")
	}

	// macLen=0 for AEAD (no separate MAC), keyLen=32 for chacha, ivLen=12
	keys, err := prf.GenerateEncryptionKeys(masterSecret, clientRandom, serverRandom, rfMacLen, prfKeyLen, prfIvLen, hashFunc)
	if err != nil {
		return err
	}

	var chacha *ChaCha
	if isClient {
		chacha, err = NewChaCha(
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ServerWriteKey, keys.ServerWriteIV,
		)
	} else {
		chacha, err = NewChaCha(
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ClientWriteKey, keys.ClientWriteIV,
		)
	}
	c.chacha.Store(chacha)

	return nil
}

// Init initializes the internal Cipher with keying material.
func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 0
		prfKeyLen = 32
		prfIvLen  = 12
	)

	return c.init(masterSecret, clientRandom, serverRandom, isClient, prfMacLen, prfKeyLen, prfIvLen, c.HashFunc())
}

// Encrypt encrypts a single TLS RecordLayer.
func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.chacha.Load().(*ChaCha)
	if !ok {
		return nil, fmt.Errorf("%w, unable to encrypt", &protocol.TemporaryError{Err: errors.New("CipherSuite has not been initialized")})
	}

	return cipherSuite.Encrypt(pkt, raw)
}

// Decrypt decrypts a single TLS RecordLayer.
func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) Decrypt(h recordlayer.Header, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.chacha.Load().(*ChaCha)
	if !ok {
		return nil, fmt.Errorf("%w, unable to decrypt", &protocol.TemporaryError{Err: errors.New("CipherSuite has not been initialized")})
	}

	return cipherSuite.Decrypt(h, raw)
}
