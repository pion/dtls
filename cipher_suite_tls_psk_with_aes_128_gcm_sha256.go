package dtls

import "github.com/pion/dtls/v2/pkg/crypto/clientcertificate"

type cipherSuiteTLSPskWithAes128GcmSha256 struct {
	cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256
}

func (c *cipherSuiteTLSPskWithAes128GcmSha256) certificateType() clientcertificate.Type {
	return clientcertificate.Type(0)
}

func (c *cipherSuiteTLSPskWithAes128GcmSha256) ID() CipherSuiteID {
	return TLS_PSK_WITH_AES_128_GCM_SHA256
}

func (c *cipherSuiteTLSPskWithAes128GcmSha256) String() string {
	return "TLS_PSK_WITH_AES_128_GCM_SHA256"
}

func (c *cipherSuiteTLSPskWithAes128GcmSha256) isPSK() bool {
	return true
}
