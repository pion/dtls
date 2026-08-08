// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//nolint:dupl // AES-128 and AES-256 implementations mirror one another.
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

// NewRecordProtection derives record protection for one DTLS 1.3 traffic
// direction and generation.
func (c *TLSAes128GcmSha256) NewRecordProtection(trafficSecret []byte) (RecordProtection13, error) {
	return newAESGCMRecordTrafficProtection13(c.HashFunc(), trafficSecret, tls13AES128GCMKeyLen)
}

// InitFromTrafficSecrets initializes DTLS 1.3 record protection from the
// negotiated client and server handshake/application traffic secrets.
func (c *TLSAes128GcmSha256) InitFromTrafficSecrets(clientSecret, serverSecret []byte, isClient bool) error {
	return c.initFromTrafficSecrets13(clientSecret, serverSecret, isClient, c.newRecordProtection)
}

func (c *TLSAes128GcmSha256) newRecordProtection(
	localTrafficSecret, remoteTrafficSecret []byte,
) (*recordProtection13, error) {
	return newAES128GCMRecordProtection13(c.HashFunc(), localTrafficSecret, remoteTrafficSecret)
}
