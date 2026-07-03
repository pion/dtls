// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha512"
	"hash"
)

// TLSAes256GcmSha384 represents the TLS_AES_256_GCM_SHA384 CipherSuite.
type TLSAes256GcmSha384 struct {
	TLS13CipherSuite
}

// NewTLSAes256GcmSha384 returns the TLS_AES_256_GCM_SHA384 CipherSuite.
func NewTLSAes256GcmSha384() *TLSAes256GcmSha384 {
	return &TLSAes256GcmSha384{}
}

// ID returns the ID of the CipherSuite.
func (c *TLSAes256GcmSha384) ID() ID {
	return TLS_AES_256_GCM_SHA384
}

func (c *TLSAes256GcmSha384) String() string {
	return "TLS_AES_256_GCM_SHA384"
}

// HashFunc returns the hashing func for this CipherSuite.
func (c *TLSAes256GcmSha384) HashFunc() func() hash.Hash {
	return sha512.New384
}

// InitFromTrafficSecrets13 initializes DTLS 1.3 record protection from the
// negotiated client and server handshake/application traffic secrets.
func (c *TLSAes256GcmSha384) InitFromTrafficSecrets13(clientSecret, serverSecret []byte, isClient bool) error {
	return c.initFromTrafficSecrets13(clientSecret, serverSecret, isClient, c.newRecordProtection)
}

func (c *TLSAes256GcmSha384) newRecordProtection(
	localTrafficSecret, remoteTrafficSecret []byte,
) (*recordProtection13, error) {
	return newAES256GCMRecordProtection13(c.HashFunc(), localTrafficSecret, remoteTrafficSecret)
}
