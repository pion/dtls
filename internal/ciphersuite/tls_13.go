// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"

	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

var errCipherSuiteRecordProtectionNotImplemented = &protocol.TemporaryError{
	// todo: implement
	// nolint:godox
	Err: errors.New("DTLS 1.3 cipher suite record protection is not implemented"), //nolint:err113
}

// TLS13CipherSuite is metadata for a TLS 1.3 cipher suite. TLS 1.3 cipher
// suites only identify the AEAD and hash; authentication and key exchange are
// negotiated independently.
type TLS13CipherSuite struct {
	id       ID
	hashFunc func() hash.Hash
}

// NewTLSAes128GcmSha256 returns metadata for TLS_AES_128_GCM_SHA256.
func NewTLSAes128GcmSha256() *TLS13CipherSuite {
	return &TLS13CipherSuite{id: TLS_AES_128_GCM_SHA256, hashFunc: sha256.New}
}

// NewTLSAes256GcmSha384 returns metadata for TLS_AES_256_GCM_SHA384.
func NewTLSAes256GcmSha384() *TLS13CipherSuite {
	return &TLS13CipherSuite{id: TLS_AES_256_GCM_SHA384, hashFunc: sha512.New384}
}

// NewTLSChacha20Poly1305Sha256 returns metadata for TLS_CHACHA20_POLY1305_SHA256.
func NewTLSChacha20Poly1305Sha256() *TLS13CipherSuite {
	return &TLS13CipherSuite{id: TLS_CHACHA20_POLY1305_SHA256, hashFunc: sha256.New}
}

func (c *TLS13CipherSuite) CertificateType() clientcertificate.Type {
	return 0
}

func (c *TLS13CipherSuite) KeyExchangeAlgorithm() KeyExchangeAlgorithm {
	return KeyExchangeAlgorithmNone
}

func (c *TLS13CipherSuite) ECC() bool {
	return true
}

func (c *TLS13CipherSuite) ID() ID {
	return c.id
}

func (c *TLS13CipherSuite) String() string {
	return c.ID().String()
}

func (c *TLS13CipherSuite) HashFunc() func() hash.Hash {
	return c.hashFunc
}

func (c *TLS13CipherSuite) AuthenticationType() AuthenticationType {
	return AuthenticationTypeAnonymous
}

func (c *TLS13CipherSuite) IsInitialized() bool {
	return false
}

func (c *TLS13CipherSuite) Init(_, _, _ []byte, _ bool) error {
	return errCipherSuiteRecordProtectionNotImplemented
}

func (c *TLS13CipherSuite) Encrypt(_ *recordlayer.RecordLayer, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteRecordProtectionNotImplemented)
}

func (c *TLS13CipherSuite) Decrypt(_ recordlayer.Header, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteRecordProtectionNotImplemented)
}
