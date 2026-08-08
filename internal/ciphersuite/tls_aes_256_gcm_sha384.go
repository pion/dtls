// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import "crypto/sha512"

// TLSAes256GcmSha384 represents the TLS_AES_256_GCM_SHA384 CipherSuite.
type TLSAes256GcmSha384 struct {
	tlsAESGCMCipherSuite
}

// NewTLSAes256GcmSha384 returns the TLS_AES_256_GCM_SHA384 CipherSuite.
func NewTLSAes256GcmSha384() *TLSAes256GcmSha384 {
	return &TLSAes256GcmSha384{
		tlsAESGCMCipherSuite: newTLSAESGCMCipherSuite(
			TLS_AES_256_GCM_SHA384,
			sha512.New384,
			tls13AES256GCMKeyLen,
		),
	}
}
