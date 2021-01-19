package dtls

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"sync/atomic"

	"github.com/pion/dtls/v2/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v2/pkg/crypto/prf"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
)

type cipherSuiteAes128Ccm struct {
	ccm                   atomic.Value // *cryptoCCM
	clientCertificateType clientcertificate.Type
	id                    CipherSuiteID
	psk                   bool
	cryptoCCMTagLen       cryptoCCMTagLen
}

func newCipherSuiteAes128Ccm(clientCertificateType clientcertificate.Type, id CipherSuiteID, psk bool, cryptoCCMTagLen cryptoCCMTagLen) *cipherSuiteAes128Ccm {
	return &cipherSuiteAes128Ccm{
		clientCertificateType: clientCertificateType,
		id:                    id,
		psk:                   psk,
		cryptoCCMTagLen:       cryptoCCMTagLen,
	}
}

func (c *cipherSuiteAes128Ccm) certificateType() clientcertificate.Type {
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
	return c.ccm.Load() != nil
}

func (c *cipherSuiteAes128Ccm) init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 0
		prfKeyLen = 16
		prfIvLen  = 4
	)

	keys, err := prf.GenerateEncryptionKeys(masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, c.hashFunc())
	if err != nil {
		return err
	}

	var ccm *cryptoCCM
	if isClient {
		ccm, err = newCryptoCCM(c.cryptoCCMTagLen, keys.ClientWriteKey, keys.ClientWriteIV, keys.ServerWriteKey, keys.ServerWriteIV)
	} else {
		ccm, err = newCryptoCCM(c.cryptoCCMTagLen, keys.ServerWriteKey, keys.ServerWriteIV, keys.ClientWriteKey, keys.ClientWriteIV)
	}
	c.ccm.Store(ccm)

	return err
}

func (c *cipherSuiteAes128Ccm) encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	ccm := c.ccm.Load()
	if ccm == nil { // !c.isInitialized()
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return ccm.(*cryptoCCM).encrypt(pkt, raw)
}

func (c *cipherSuiteAes128Ccm) decrypt(raw []byte) ([]byte, error) {
	ccm := c.ccm.Load()
	if ccm == nil { // !c.isInitialized()
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return ccm.(*cryptoCCM).decrypt(raw)
}
