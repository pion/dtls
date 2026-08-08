// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import "hash"

// tlsAESGCMCipherSuite provides the common TLS 1.3 AES-GCM cipher suite
// behavior, parameterized by its identifier, hash, and AES key size.
type tlsAESGCMCipherSuite struct {
	TLS13CipherSuite

	id       ID
	hashFunc func() hash.Hash
	keyLen   int
}

func newTLSAESGCMCipherSuite(id ID, hashFunc func() hash.Hash, keyLen int) tlsAESGCMCipherSuite {
	return tlsAESGCMCipherSuite{
		id:       id,
		hashFunc: hashFunc,
		keyLen:   keyLen,
	}
}

// ID returns the ID of the CipherSuite.
func (c *tlsAESGCMCipherSuite) ID() ID {
	return c.id
}

func (c *tlsAESGCMCipherSuite) String() string {
	return c.id.String()
}

// HashFunc returns the hashing func for this CipherSuite.
func (c *tlsAESGCMCipherSuite) HashFunc() func() hash.Hash {
	return c.hashFunc
}

// NewRecordProtection derives record protection for one DTLS 1.3 traffic
// direction and generation.
func (c *tlsAESGCMCipherSuite) NewRecordProtection(trafficSecret []byte) (RecordProtection13, error) {
	return newAESGCMRecordTrafficProtection13(c.HashFunc(), trafficSecret, c.keyLen)
}

// InitFromTrafficSecrets initializes DTLS 1.3 record protection from the
// negotiated client and server handshake/application traffic secrets.
func (c *tlsAESGCMCipherSuite) InitFromTrafficSecrets(clientSecret, serverSecret []byte, isClient bool) error {
	return c.initFromTrafficSecrets13(clientSecret, serverSecret, isClient, c.newRecordProtection)
}

func (c *tlsAESGCMCipherSuite) newRecordProtection(
	localTrafficSecret, remoteTrafficSecret []byte,
) (*recordProtection13, error) {
	return newAESGCMRecordProtection13(c.HashFunc(), localTrafficSecret, remoteTrafficSecret, c.keyLen)
}
