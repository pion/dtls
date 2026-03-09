// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
)

// NewTLSPskWithAes256Ccm returns the TLS_PSK_WITH_AES_256_CCM CipherSuite.
func NewTLSPskWithAes256Ccm() *Aes256Ccm {
	return newAes256Ccm(
		clientcertificate.Type(0),
		TLS_PSK_WITH_AES_256_CCM,
		true,
		ciphersuite.CCMTagLength,
		KeyExchangeAlgorithmPsk,
		false,
	)
}
