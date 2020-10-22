package dtls

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"sync/atomic"
)

type CipherSuiteAes128Ccm struct {
	ccm                   atomic.Value // *CryptoCCM
	clientCertificateType ClientCertificateType
	id                    CipherSuiteID
	psk                   bool
	cryptoCCMTagLen       cryptoCCMTagLen
}

func NewCipherSuiteAes128Ccm(clientCertificateType ClientCertificateType, id CipherSuiteID, psk bool, cryptoCCMTagLen cryptoCCMTagLen) *CipherSuiteAes128Ccm {
	return &CipherSuiteAes128Ccm{
		clientCertificateType: clientCertificateType,
		id:                    id,
		psk:                   psk,
		cryptoCCMTagLen:       cryptoCCMTagLen,
	}
}

func (c *CipherSuiteAes128Ccm) CertificateType() ClientCertificateType {
	return c.clientCertificateType
}

func (c *CipherSuiteAes128Ccm) ID() CipherSuiteID {
	return c.id
}

func (c *CipherSuiteAes128Ccm) String() string {
	return c.id.String()
}

func (c *CipherSuiteAes128Ccm) HashFunc() func() hash.Hash {
	return sha256.New
}

func (c *CipherSuiteAes128Ccm) IsPSK() bool {
	return c.psk
}

func (c *CipherSuiteAes128Ccm) IsAnon() bool {
	return false
}

func (c *CipherSuiteAes128Ccm) IsInitialized() bool {
	return c.ccm.Load() != nil
}

func (c *CipherSuiteAes128Ccm) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 0
		prfKeyLen = 16
		prfIvLen  = 4
	)

	keys, err := PrfEncryptionKeys(masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, c.HashFunc())
	if err != nil {
		return err
	}

	var ccm *CryptoCCM
	if isClient {
		ccm, err = NewCryptoCCM(c.cryptoCCMTagLen, keys.ClientWriteKey, keys.ClientWriteIV, keys.ServerWriteKey, keys.ServerWriteIV)
	} else {
		ccm, err = NewCryptoCCM(c.cryptoCCMTagLen, keys.ServerWriteKey, keys.ServerWriteIV, keys.ClientWriteKey, keys.ClientWriteIV)
	}
	c.ccm.Store(ccm)

	return err
}

var errCipherSuiteNotInit = errors.New("CipherSuite has not been initialized")

func (c *CipherSuiteAes128Ccm) Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error) {
	ccm := c.ccm.Load()
	if ccm == nil { // !c.IsInitialized()
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return ccm.(*CryptoCCM).Encrypt(pkt, raw)
}

func (c *CipherSuiteAes128Ccm) Decrypt(raw []byte) ([]byte, error) {
	ccm := c.ccm.Load()
	if ccm == nil { // !c.IsInitialized()
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return ccm.(*CryptoCCM).Decrypt(raw)
}
