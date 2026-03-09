// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import "github.com/pion/dtls/v3/pkg/crypto/clientcertificate"

// TLSPskWithAes256GcmSha384 implements the TLS_PSK_WITH_AES_256_GCM_SHA384 CipherSuite.
type TLSPskWithAes256GcmSha384 struct {
	TLSEcdheEcdsaWithAes256GcmSha384
}

// CertificateType returns what type of certificate this CipherSuite exchanges.
func (c *TLSPskWithAes256GcmSha384) CertificateType() clientcertificate.Type {
	return clientcertificate.Type(0)
}

// KeyExchangeAlgorithm controls what key exchange algorithm is using during the handshake.
func (c *TLSPskWithAes256GcmSha384) KeyExchangeAlgorithm() KeyExchangeAlgorithm {
	return KeyExchangeAlgorithmPsk
}

// ID returns the ID of the CipherSuite.
func (c *TLSPskWithAes256GcmSha384) ID() ID {
	return TLS_PSK_WITH_AES_256_GCM_SHA384
}

func (c *TLSPskWithAes256GcmSha384) String() string {
	return "TLS_PSK_WITH_AES_256_GCM_SHA384"
}

// AuthenticationType controls what authentication method is using during the handshake.
func (c *TLSPskWithAes256GcmSha384) AuthenticationType() AuthenticationType {
	return AuthenticationTypePreSharedKey
}
