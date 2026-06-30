// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"fmt"
	"hash"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// TLS13CipherSuite provides behavior common to TLS 1.3 cipher suites. When
// used directly, it is metadata for suites whose record protection is not wired
// yet.
// this is a temporary struct to be removed when the record protection is wired.
type TLS13CipherSuite struct {
	id       ID
	hashFunc func() hash.Hash
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
	return dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
}

func (c *TLS13CipherSuite) Encrypt(_ *recordlayer.RecordLayer, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w, unable to encrypt", dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented)
}

func (c *TLS13CipherSuite) Decrypt(_ recordlayer.Header, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w, unable to decrypt", dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented)
}

func (c *TLS13CipherSuite) newRecordProtection(_, _ []byte) (*recordProtection13, error) {
	return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
}
