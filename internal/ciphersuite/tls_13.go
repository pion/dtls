// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"fmt"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// CipherSuiteTLS13 is the DTLS 1.3-specific cipher suite surface.
type CipherSuiteTLS13 interface {
	CipherSuite
	NewRecordProtection(trafficSecret []byte) (RecordProtection13, error)
}

// RecordProtection13 protects records for one DTLS 1.3 traffic direction and
// generation.
type RecordProtection13 interface {
	Seal(
		header recordlayer.UnifiedHeader,
		sequenceNumber uint64,
		contentType protocol.ContentType,
		plaintext []byte,
	) (recordlayer.CiphertextRecord13, error)
	Open(
		header recordlayer.UnifiedHeader,
		sequenceNumber uint64,
		encryptedRecord []byte,
	) (recordlayer.InnerPlaintext, error)
	UnmaskSequenceNumber(
		header recordlayer.UnifiedHeader,
		encryptedRecord []byte,
	) (recordlayer.UnifiedHeader, error)
}

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

// IsInitialized satisfies the generic CipherSuite contract. DTLS 1.3 record
// key readiness is tracked by state.TrafficKeys, not by the cipher suite.
func (c *TLS13CipherSuite) IsInitialized() bool {
	return true
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
