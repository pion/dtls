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

type cipherSuiteTLSPskWithAes128CbcSha256 struct {
	cbc atomic.Value // *cryptoCBC
}

func (c *cipherSuiteTLSPskWithAes128CbcSha256) certificateType() clientcertificate.Type {
	return clientcertificate.Type(0)
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

	keys, err := prf.GenerateEncryptionKeys(masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, c.hashFunc())
	if err != nil {
		return err
	}

	var cbc *cryptoCBC
	if isClient {
		cbc, err = newCryptoCBC(
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			c.hashFunc(),
		)
	} else {
		cbc, err = newCryptoCBC(
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			c.hashFunc(),
		)
	}
	c.cbc.Store(cbc)

	return err
}

func (c *cipherSuiteTLSPskWithAes128CbcSha256) encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	cbc := c.cbc.Load()
	if cbc == nil { // !c.isInitialized()
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cbc.(*cryptoCBC).encrypt(pkt, raw)
}

func (c *cipherSuiteTLSPskWithAes128CbcSha256) decrypt(raw []byte) ([]byte, error) {
	cbc := c.cbc.Load()
	if cbc == nil { // !c.isInitialized()
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cbc.(*cryptoCBC).decrypt(raw)
}
