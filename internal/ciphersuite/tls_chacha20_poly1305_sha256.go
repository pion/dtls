// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"hash"
)

// TLSChacha20Poly1305Sha256 represents the TLS_CHACHA20_POLY1305_SHA256 CipherSuite.
type TLSChacha20Poly1305Sha256 struct {
	TLS13CipherSuite
}

// NewTLSChacha20Poly1305Sha256 returns the TLS_CHACHA20_POLY1305_SHA256 CipherSuite.
func NewTLSChacha20Poly1305Sha256() *TLSChacha20Poly1305Sha256 {
	return &TLSChacha20Poly1305Sha256{}
}

// ID returns the ID of the CipherSuite.
func (c *TLSChacha20Poly1305Sha256) ID() ID {
	return TLS_CHACHA20_POLY1305_SHA256
}

func (c *TLSChacha20Poly1305Sha256) String() string {
	return "TLS_CHACHA20_POLY1305_SHA256"
}

// HashFunc returns the hashing func for this CipherSuite.
func (c *TLSChacha20Poly1305Sha256) HashFunc() func() hash.Hash {
	return sha256.New
}

// InitFromTrafficSecrets13 initializes DTLS 1.3 record protection from the
// negotiated client and server handshake/application traffic secrets.
func (c *TLSChacha20Poly1305Sha256) InitFromTrafficSecrets13(clientSecret, serverSecret []byte, isClient bool) error {
	return c.initFromTrafficSecrets13(clientSecret, serverSecret, isClient, c.newRecordProtection)
}

func (c *TLSChacha20Poly1305Sha256) newRecordProtection(
	localTrafficSecret, remoteTrafficSecret []byte,
) (*recordProtection13, error) {
	return newChaCha20Poly1305RecordProtection13(c.HashFunc(), localTrafficSecret, remoteTrafficSecret)
}
