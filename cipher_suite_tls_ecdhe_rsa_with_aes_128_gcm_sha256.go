package dtls

import "github.com/pion/dtls/v2/pkg/crypto/clientcertificate"

type cipherSuiteTLSEcdheRsaWithAes128GcmSha256 struct {
	cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256
}

func (c *cipherSuiteTLSEcdheRsaWithAes128GcmSha256) certificateType() clientcertificate.Type {
	return clientcertificate.RSASign
}

func (c *cipherSuiteTLSEcdheRsaWithAes128GcmSha256) ID() CipherSuiteID {
	return TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
}

func (c *cipherSuiteTLSEcdheRsaWithAes128GcmSha256) String() string {
	return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
}
