// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"fmt"
	"sync/atomic"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// CipherSuiteTLS13 is the DTLS 1.3-specific cipher suite surface.
type CipherSuiteTLS13 interface {
	CipherSuite
	InitFromTrafficSecrets13(clientSecret, serverSecret []byte, isClient bool) error
}

// TLS13CipherSuite provides behavior common to TLS 1.3 cipher suites. TLS 1.3
// cipher suites only identify the AEAD and hash; authentication and key
// exchange are negotiated independently.
type TLS13CipherSuite struct {
	recordProtection atomic.Value // *recordProtection13
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

func (c *TLS13CipherSuite) AuthenticationType() AuthenticationType {
	return AuthenticationTypeAnonymous
}

func (c *TLS13CipherSuite) IsInitialized() bool {
	return c.recordProtection.Load() != nil
}

func (c *TLS13CipherSuite) initFromTrafficSecrets13(
	clientSecret, serverSecret []byte,
	isClient bool,
	newRecordProtection func(localTrafficSecret, remoteTrafficSecret []byte) (*recordProtection13, error),
) error {
	if newRecordProtection == nil {
		return dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	localSecret, remoteSecret := localRemoteTrafficSecrets13(clientSecret, serverSecret, isClient)
	protection, err := newRecordProtection(localSecret, remoteSecret)
	if err != nil {
		return err
	}

	c.recordProtection.Store(protection)

	return nil
}

func (c *TLS13CipherSuite) getRecordProtection13() (*recordProtection13, bool) {
	protection, ok := c.recordProtection.Load().(*recordProtection13)

	return protection, ok
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

func localRemoteTrafficSecrets13(
	clientSecret, serverSecret []byte,
	isClient bool,
) (localSecret, remoteSecret []byte) {
	if isClient {
		return clientSecret, serverSecret
	}

	return serverSecret, clientSecret
}
