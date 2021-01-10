package dtls

import "github.com/pion/dtls/v2/pkg/crypto/clientcertificate"

func newCipherSuiteTLSEcdheEcdsaWithAes128Ccm() *cipherSuiteAes128Ccm {
	return newCipherSuiteAes128Ccm(clientcertificate.ECDSASign, TLS_ECDHE_ECDSA_WITH_AES_128_CCM, false, cryptoCCMTagLength)
}
