package dtls

import (
	"crypto/sha256"
	"errors"
	"hash"
	"sync"
)

type cipherSuiteAes128Ccm struct {
	ccm                   *cryptoCCM
	clientCertificateType clientCertificateType
	id                    CipherSuiteID
	psk                   bool
	cryptoCCMTagLen       cryptoCCMTagLen
	sync.RWMutex
}

func newCipherSuiteAes128Ccm(clientCertificateType clientCertificateType, id CipherSuiteID, psk bool, cryptoCCMTagLen cryptoCCMTagLen) *cipherSuiteAes128Ccm {
	return &cipherSuiteAes128Ccm{
		clientCertificateType: clientCertificateType,
		id:                    id,
		psk:                   psk,
		cryptoCCMTagLen:       cryptoCCMTagLen,
	}
}

func (c *cipherSuiteAes128Ccm) certificateType() clientCertificateType {
	return c.clientCertificateType
}

func (c *cipherSuiteAes128Ccm) ID() CipherSuiteID {
	return c.id
}

func (c *cipherSuiteAes128Ccm) String() string {
	return c.id.String()
}

func (c *cipherSuiteAes128Ccm) hashFunc() func() hash.Hash {
	return sha256.New
}

func (c *cipherSuiteAes128Ccm) isPSK() bool {
	return c.psk
}

func (c *cipherSuiteAes128Ccm) isInitialized() bool {
	c.RLock()
	defer c.RUnlock()
	return c.ccm != nil
}

func (c *cipherSuiteAes128Ccm) init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
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
		c.ccm, err = newCryptoCCM(c.cryptoCCMTagLen, keys.clientWriteKey, keys.clientWriteIV, keys.serverWriteKey, keys.serverWriteIV)
	} else {
		c.ccm, err = newCryptoCCM(c.cryptoCCMTagLen, keys.serverWriteKey, keys.serverWriteIV, keys.clientWriteKey, keys.clientWriteIV)
	}

	return err
}

func (c *cipherSuiteAes128Ccm) encrypt(pkt *recordLayer, raw []byte) ([]byte, error) {
	if !c.isInitialized() {
		return nil, errors.New("CipherSuite has not been initialized, unable to encrypt")
	}

	return c.ccm.encrypt(pkt, raw)
}

func (c *cipherSuiteAes128Ccm) decrypt(raw []byte) ([]byte, error) {
	if !c.isInitialized() {
		return nil, errors.New("CipherSuite has not been initialized, unable to decrypt ")
	}

	return c.ccm.decrypt(raw)
}
