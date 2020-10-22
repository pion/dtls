package dtls

func NewCipherSuiteTLSPskWithAes128Ccm() *CipherSuiteAes128Ccm {
	return NewCipherSuiteAes128Ccm(ClientCertificateType(0), TLS_PSK_WITH_AES_128_CCM, true, cryptoCCMTagLength)
}
