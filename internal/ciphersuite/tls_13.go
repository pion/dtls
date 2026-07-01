// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"fmt"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// TLS13CipherSuite provides behavior common to TLS 1.3 cipher suites. TLS 1.3
// cipher suites only identify the AEAD and hash; authentication and key
// exchange are negotiated independently.
type TLS13CipherSuite struct{}

func (c *TLS13CipherSuite) CertificateType() clientcertificate.Type {
	return 0
}

func (c *TLS13CipherSuite) KeyExchangeAlgorithm() KeyExchangeAlgorithm {
	return KeyExchangeAlgorithmNone
}

func (c *TLS13CipherSuite) ECC() bool {
	return true
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
