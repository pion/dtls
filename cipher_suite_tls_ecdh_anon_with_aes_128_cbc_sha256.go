package dtls

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"sync/atomic"
)

type CipherSuiteTLSEcdhAnonWithAes128CbcSha256 struct {
	cbc atomic.Value // *CryptoCBC
	id  CipherSuiteID
}

func NewCipherSuiteTLSEcdhAnonWithAes128CbcSha256(id CipherSuiteID) *CipherSuiteTLSEcdhAnonWithAes128CbcSha256 {
	return &CipherSuiteTLSEcdhAnonWithAes128CbcSha256{
		id: id,
	}
}

func (c *CipherSuiteTLSEcdhAnonWithAes128CbcSha256) CertificateType() ClientCertificateType {
	return ClientCertificateType(0)
}

func (c *CipherSuiteTLSEcdhAnonWithAes128CbcSha256) ID() CipherSuiteID {
	return c.id
}

func (c *CipherSuiteTLSEcdhAnonWithAes128CbcSha256) String() string {
	return "TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256"
}

func (c *CipherSuiteTLSEcdhAnonWithAes128CbcSha256) HashFunc() func() hash.Hash {
	return sha256.New
}

func (c *CipherSuiteTLSEcdhAnonWithAes128CbcSha256) IsPSK() bool {
	return false
}

func (c *CipherSuiteTLSEcdhAnonWithAes128CbcSha256) IsAnon() bool {
	return true
}

func (c *CipherSuiteTLSEcdhAnonWithAes128CbcSha256) IsInitialized() bool {
	return c.cbc.Load() != nil
}

func (c *CipherSuiteTLSEcdhAnonWithAes128CbcSha256) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 20
		prfKeyLen = 32
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
		)
	} else {
		cbc, err = NewCryptoCBC(
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
		)
	}
	c.cbc.Store(cbc)

	return err
}

func (c *CipherSuiteTLSEcdhAnonWithAes128CbcSha256) Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error) {
	cbc := c.cbc.Load()
	if cbc == nil { // !c.IsInitialized()
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return cbc.(*CryptoCBC).Encrypt(pkt, raw)
}

func (c *CipherSuiteTLSEcdhAnonWithAes128CbcSha256) Decrypt(raw []byte) ([]byte, error) {
	cbc := c.cbc.Load()
	if cbc == nil { // !c.IsInitialized()
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cbc.(*CryptoCBC).Decrypt(raw)
}
