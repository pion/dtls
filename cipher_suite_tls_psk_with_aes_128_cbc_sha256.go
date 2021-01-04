package dtls

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"sync/atomic"
)

type CipherSuiteTLSPskWithAes128CbcSha256 struct {
	cbc atomic.Value // *cryptoCBC
}

func (c *CipherSuiteTLSPskWithAes128CbcSha256) CertificateType() ClientCertificateType {
	return ClientCertificateType(0)
}

func (c *CipherSuiteTLSPskWithAes128CbcSha256) ID() CipherSuiteID {
	return TLS_PSK_WITH_AES_128_CBC_SHA256
}

func (c *CipherSuiteTLSPskWithAes128CbcSha256) String() string {
	return "TLS_PSK_WITH_AES_128_CBC_SHA256"
}

func (c *CipherSuiteTLSPskWithAes128CbcSha256) HashFunc() func() hash.Hash {
	return sha256.New
}

func (c *CipherSuiteTLSPskWithAes128CbcSha256) IsPSK() bool {
	return true
}

func (c *CipherSuiteTLSPskWithAes128CbcSha256) IsAnon() bool {
	return false
}

func (c *CipherSuiteTLSPskWithAes128CbcSha256) IsInitialized() bool {
	return c.cbc.Load() != nil
}

func (c *CipherSuiteTLSPskWithAes128CbcSha256) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 32
		prfKeyLen = 16
		prfIvLen  = 16
	)

	keys, err := PrfEncryptionKeys(masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, c.HashFunc())
	if err != nil {
		return err
	}

	var cbc *CryptoCBC
	if isClient {
		cbc, err = NewCryptoCBC(
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			c.HashFunc(),
		)
	} else {
		cbc, err = NewCryptoCBC(

			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			c.HashFunc(),
		)
	}
	c.cbc.Store(cbc)

	return err
}

func (c *CipherSuiteTLSPskWithAes128CbcSha256) Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error) {
	cbc := c.cbc.Load()
	if cbc == nil { // !c.isInitialized()
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cbc.(*CryptoCBC).Encrypt(pkt, raw)
}

func (c *CipherSuiteTLSPskWithAes128CbcSha256) Decrypt(raw []byte) ([]byte, error) {
	cbc := c.cbc.Load()
	if cbc == nil { // !c.isInitialized()
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cbc.(*CryptoCBC).Decrypt(raw)
}
