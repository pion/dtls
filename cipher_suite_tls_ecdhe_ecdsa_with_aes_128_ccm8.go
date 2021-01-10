package dtls

import "github.com/pion/dtls/v2/pkg/crypto/clientcertificate"

func newCipherSuiteTLSEcdheEcdsaWithAes128Ccm8() *cipherSuiteAes128Ccm {
	return newCipherSuiteAes128Ccm(clientcertificate.ECDSASign, TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, false, cryptoCCM8TagLength)
}
