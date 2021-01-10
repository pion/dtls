package dtls

import "github.com/pion/dtls/v2/pkg/crypto/clientcertificate"

func newCipherSuiteTLSPskWithAes128Ccm() *cipherSuiteAes128Ccm {
	return newCipherSuiteAes128Ccm(clientcertificate.Type(0), TLS_PSK_WITH_AES_128_CCM, true, cryptoCCMTagLength)
}
