package dtls

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"sync/atomic"
)

type CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256 struct {
	gcm atomic.Value // *CryptoGCM
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256) CertificateType() ClientCertificateType {
	return ClientCertificateTypeECDSASign
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256) ID() CipherSuiteID {
	return TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256) String() string {
	return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256) HashFunc() func() hash.Hash {
	return sha256.New
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256) IsPSK() bool {
	return false
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256) IsAnon() bool {
	return false
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256) IsInitialized() bool {
	return c.gcm.Load() != nil
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 0
		prfKeyLen = 16
		prfIvLen  = 4
	)

	keys, err := PrfEncryptionKeys(masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, c.HashFunc())
	if err != nil {
		return err
	}

	var gcm *CryptoGCM
	if isClient {
		gcm, err = NewCryptoGCM(keys.ClientWriteKey, keys.ClientWriteIV, keys.ServerWriteKey, keys.ServerWriteIV)
	} else {
		gcm, err = NewCryptoGCM(keys.ServerWriteKey, keys.ServerWriteIV, keys.ClientWriteKey, keys.ClientWriteIV)
	}
	c.gcm.Store(gcm)

	return err
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256) Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error) {
	gcm := c.gcm.Load()
	if gcm == nil { // !c.IsInitialized()
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return gcm.(*CryptoGCM).Encrypt(pkt, raw)
}

func (c *CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256) Decrypt(raw []byte) ([]byte, error) {
	gcm := c.gcm.Load()
	if gcm == nil { // !c.IsInitialized()
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return gcm.(*CryptoGCM).Decrypt(raw)
}
