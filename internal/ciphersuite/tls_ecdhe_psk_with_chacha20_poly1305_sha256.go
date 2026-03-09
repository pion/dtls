// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import "github.com/pion/dtls/v3/pkg/crypto/clientcertificate"

// TLSEcdhePskWithChacha20Poly1305Sha256 implements the TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 CipherSuite.
type TLSEcdhePskWithChacha20Poly1305Sha256 struct {
	TLSEcdheEcdsaWithChacha20Poly1305Sha256
}

// CertificateType returns what type of certificate this CipherSuite exchanges.
func (c *TLSEcdhePskWithChacha20Poly1305Sha256) CertificateType() clientcertificate.Type {
	return clientcertificate.Type(0)
}

// KeyExchangeAlgorithm controls what key exchange algorithm is using during the handshake.
func (c *TLSEcdhePskWithChacha20Poly1305Sha256) KeyExchangeAlgorithm() KeyExchangeAlgorithm {
	return KeyExchangeAlgorithmPsk | KeyExchangeAlgorithmEcdhe
}

// ID returns the ID of the CipherSuite.
func (c *TLSEcdhePskWithChacha20Poly1305Sha256) ID() ID {
	return TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
}

// String returns the string representation of the cipher's ID.
func (c *TLSEcdhePskWithChacha20Poly1305Sha256) String() string {
	return c.ID().String()
}

// AuthenticationType controls what authentication method is using during the handshake.
func (c *TLSEcdhePskWithChacha20Poly1305Sha256) AuthenticationType() AuthenticationType {
	return AuthenticationTypePreSharedKey
}
