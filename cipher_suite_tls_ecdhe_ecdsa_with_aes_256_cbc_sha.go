package dtls

import (
	"crypto/sha1"
	"fmt"
	"hash"
	"sync/atomic"
)

type CipherSuiteTLSEcdheEcdsaWithAes256CbcSha struct {
	cbc atomic.Value // *CryptoCBC
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes256CbcSha) CertificateType() ClientCertificateType {
	return ClientCertificateTypeECDSASign
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes256CbcSha) ID() CipherSuiteID {
	return TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes256CbcSha) String() string {
	return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes256CbcSha) HashFunc() func() hash.Hash {
	return sha1.New
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes256CbcSha) IsPSK() bool {
	return false
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes256CbcSha) IsAnon() bool {
	return false
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes256CbcSha) IsInitialized() bool {
	return c.cbc.Load() != nil
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes256CbcSha) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
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
			c.HashFunc(),
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
		)
	} else {
		cbc, err = NewCryptoCBC(
			c.HashFunc(),
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
		)
	}
	c.cbc.Store(cbc)

	return err
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes256CbcSha) Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error) {
	cbc := c.cbc.Load()
	if cbc == nil { // !c.IsInitialized()
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return cbc.(*CryptoCBC).Encrypt(pkt, raw)
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes256CbcSha) Decrypt(raw []byte) ([]byte, error) {
	cbc := c.cbc.Load()
	if cbc == nil { // !c.IsInitialized()
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cbc.(*CryptoCBC).Decrypt(raw)
}
