package dtls

import "github.com/pion/dtls/v2/pkg/crypto/clientcertificate"

type cipherSuiteTLSEcdheRsaWithAes256CbcSha struct {
	cipherSuiteTLSEcdheEcdsaWithAes256CbcSha
}

func (c *cipherSuiteTLSEcdheRsaWithAes256CbcSha) certificateType() clientcertificate.Type {
	return clientcertificate.RSASign
}

func (c *cipherSuiteTLSEcdheRsaWithAes256CbcSha) ID() CipherSuiteID {
	return TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
}

func (c *cipherSuiteTLSEcdheRsaWithAes256CbcSha) String() string {
	return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
}
