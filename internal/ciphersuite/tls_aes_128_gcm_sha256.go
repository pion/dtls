// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"hash"
)

// TLSAes128GcmSha256 represents the TLS_AES_128_GCM_SHA256 CipherSuite.
type TLSAes128GcmSha256 struct {
	TLS13CipherSuite
}

// NewTLSAes128GcmSha256 returns the TLS_AES_128_GCM_SHA256 CipherSuite.
func NewTLSAes128GcmSha256() *TLSAes128GcmSha256 {
	return &TLSAes128GcmSha256{}
}

// ID returns the ID of the CipherSuite.
func (c *TLSAes128GcmSha256) ID() ID {
	return TLS_AES_128_GCM_SHA256
}

func (c *TLSAes128GcmSha256) String() string {
	return "TLS_AES_128_GCM_SHA256"
}

// HashFunc returns the hashing func for this CipherSuite.
func (c *TLSAes128GcmSha256) HashFunc() func() hash.Hash {
	return sha256.New
}

func (c *TLSAes128GcmSha256) newRecordProtection(
	localTrafficSecret, remoteTrafficSecret []byte,
) (*recordProtection13, error) {
	return newAES128GCMRecordProtection13(c.HashFunc(), localTrafficSecret, remoteTrafficSecret)
}
