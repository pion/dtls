package dtls

import (
	"crypto/sha256"
	"errors"
	"hash"
	"sync"
)

type cipherSuiteTLSEcdheEcdsaWithAes128Ccm struct {
	ccm *cryptoCCM
	sync.RWMutex
}

func (c *cipherSuiteTLSEcdheEcdsaWithAes128Ccm) certificateType() clientCertificateType {
	return clientCertificateTypeECDSASign
}

func (c *cipherSuiteTLSEcdheEcdsaWithAes128Ccm) ID() CipherSuiteID {
	return TLS_ECDHE_ECDSA_WITH_AES_128_CCM
}

func (c *cipherSuiteTLSEcdheEcdsaWithAes128Ccm) String() string {
	return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"
}

func (c *cipherSuiteTLSEcdheEcdsaWithAes128Ccm) hashFunc() func() hash.Hash {
	return sha256.New
}

func (c *cipherSuiteTLSEcdheEcdsaWithAes128Ccm) isPSK() bool {
	return false
}

func (c *cipherSuiteTLSEcdheEcdsaWithAes128Ccm) isInitialized() bool {
	c.RLock()
	defer c.RUnlock()
	return c.ccm != nil
}

func (c *cipherSuiteTLSEcdheEcdsaWithAes128Ccm) init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 0
		prfKeyLen = 16
		prfIvLen  = 4
	)

	keys, err := prfEncryptionKeys(masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, c.hashFunc())
	if err != nil {
		return err
	}

	c.Lock()
	defer c.Unlock()
	if isClient {
		c.ccm, err = newCryptoCCM(cryptoCCMTagLength, keys.clientWriteKey, keys.clientWriteIV, keys.serverWriteKey, keys.serverWriteIV)
	} else {
		c.ccm, err = newCryptoCCM(cryptoCCMTagLength, keys.serverWriteKey, keys.serverWriteIV, keys.clientWriteKey, keys.clientWriteIV)
	}

	return err
}

func (c *cipherSuiteTLSEcdheEcdsaWithAes128Ccm) encrypt(pkt *recordLayer, raw []byte) ([]byte, error) {
	if !c.isInitialized() {
		return nil, errors.New("CipherSuite has not been initialized, unable to encrypt")
	}

	return c.ccm.encrypt(pkt, raw)
}

func (c *cipherSuiteTLSEcdheEcdsaWithAes128Ccm) decrypt(raw []byte) ([]byte, error) {
	if !c.isInitialized() {
		return nil, errors.New("CipherSuite has not been initialized, unable to decrypt ")
	}

	return c.ccm.decrypt(raw)
}
