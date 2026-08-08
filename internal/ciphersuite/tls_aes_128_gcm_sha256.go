// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import "crypto/sha256"

// TLSAes128GcmSha256 represents the TLS_AES_128_GCM_SHA256 CipherSuite.
type TLSAes128GcmSha256 struct {
	tlsAESGCMCipherSuite
}

// NewTLSAes128GcmSha256 returns the TLS_AES_128_GCM_SHA256 CipherSuite.
func NewTLSAes128GcmSha256() *TLSAes128GcmSha256 {
	return &TLSAes128GcmSha256{
		tlsAESGCMCipherSuite: newTLSAESGCMCipherSuite(
			TLS_AES_128_GCM_SHA256,
			sha256.New,
			tls13AES128GCMKeyLen,
		),
	}
}
