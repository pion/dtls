package dtls

import (
	"crypto/sha256"
	"errors"
	"hash"
	"sync/atomic"
)

type cipherSuiteTLSPskWithAes128CbcSha256 struct {
	cbc atomic.Value // *cryptoCBC
}

func (c *cipherSuiteTLSPskWithAes128CbcSha256) certificateType() clientCertificateType {
	return clientCertificateType(0)
}

func (c *cipherSuiteTLSPskWithAes128CbcSha256) ID() CipherSuiteID {
	return TLS_PSK_WITH_AES_128_CBC_SHA256
}

func (c *cipherSuiteTLSPskWithAes128CbcSha256) String() string {
	return "TLS_PSK_WITH_AES_128_CBC_SHA256"
}

func (c *cipherSuiteTLSPskWithAes128CbcSha256) hashFunc() func() hash.Hash {
	return sha256.New
}

func (c *cipherSuiteTLSPskWithAes128CbcSha256) isPSK() bool {
	return true
}

func (c *cipherSuiteTLSPskWithAes128CbcSha256) isInitialized() bool {
	return c.cbc.Load() != nil
}

func (c *cipherSuiteTLSPskWithAes128CbcSha256) init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 32
		prfKeyLen = 16
		prfIvLen  = 16
	)

	keys, err := prfEncryptionKeys(masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, c.hashFunc())
	if err != nil {
		return err
	}

	var cbc *cryptoCBC
	if isClient {
		cbc, err = newCryptoCBC(
			keys.clientWriteKey, keys.clientWriteIV, keys.clientMACKey,
			keys.serverWriteKey, keys.serverWriteIV, keys.serverMACKey,
			c.hashFunc(),
		)
	} else {
		cbc, err = newCryptoCBC(
			keys.serverWriteKey, keys.serverWriteIV, keys.serverMACKey,
			keys.clientWriteKey, keys.clientWriteIV, keys.clientMACKey,
			c.hashFunc(),
		)
	}
	c.cbc.Store(cbc)

	return err
}

func (c *cipherSuiteTLSPskWithAes128CbcSha256) encrypt(pkt *recordLayer, raw []byte) ([]byte, error) {
	cbc := c.cbc.Load()
	if cbc == nil { // !c.isInitialized()
		return nil, errors.New("CipherSuite has not been initialized, unable to encrypt")
	}

	return cbc.(*cryptoCBC).encrypt(pkt, raw)
}

func (c *cipherSuiteTLSPskWithAes128CbcSha256) decrypt(raw []byte) ([]byte, error) {
	cbc := c.cbc.Load()
	if cbc == nil { // !c.isInitialized()
		return nil, errors.New("CipherSuite has not been initialized, unable to decrypt ")
	}

	return cbc.(*cryptoCBC).decrypt(raw)
}
