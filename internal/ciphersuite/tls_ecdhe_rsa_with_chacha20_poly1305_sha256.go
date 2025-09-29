package ciphersuite

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"sync"
	"sync/atomic"

	"github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

type TLSEcdheRsaWithChaCha20Poly1305Sha256 struct {
	chacha atomic.Value
	// key lengths
	keyLen int
	ivLen  int

	mu   sync.RWMutex
	name string
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) CertificateType() clientcertificate.Type {
	return clientcertificate.ECDSASign
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) KeyExchangeAlgorithm() KeyExchangeAlgorithm {
	return KeyExchangeAlgorithmEcdhe
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) ECC() bool {
	return true
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) ID() ID {

	return TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) String() string {
	return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) HashFunc() func() hash.Hash {
	return sha256.New
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) AuthenticationType() AuthenticationType {
	return AuthenticationTypeCertificate
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) IsInitialized() bool {
	return c.chacha.Load() != nil
}

func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if masterSecret == nil {
		return errors.New("masterSecret is nil")
	}

	// macLen=0 for AEAD (no separate MAC), keyLen=32 for chacha, ivLen=12
	keys, err := prf.GenerateEncryptionKeys(masterSecret, clientRandom, serverRandom, 0, c.keyLen, c.ivLen, c.HashFunc())
	if err != nil {
		return err
	}

	var chacha *ciphersuite.ChaCha
	if isClient {
		chacha, err = ciphersuite.NewChaCha(
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ServerWriteKey, keys.ServerWriteIV,
		)
	} else {
		chacha, err = ciphersuite.NewChaCha(
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ClientWriteKey, keys.ClientWriteIV,
		)
	}
	c.chacha.Store(chacha)

	return nil
}

// Encrypt encrypts a single TLS RecordLayer.
func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.chacha.Load().(*ciphersuite.ChaCha)
	if !ok {
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Encrypt(pkt, raw)
}

// Decrypt decrypts a single TLS RecordLayer.
func (c *TLSEcdheRsaWithChaCha20Poly1305Sha256) Decrypt(h recordlayer.Header, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.chacha.Load().(*ciphersuite.ChaCha)
	if !ok {
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Decrypt(h, raw)
}
