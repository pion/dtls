package dtls

func NewCipherSuiteTLSPskWithAes128Ccm8() *CipherSuiteAes128Ccm {
	return NewCipherSuiteAes128Ccm(ClientCertificateType(0), TLS_PSK_WITH_AES_128_CCM_8, true, cryptoCCM8TagLength)
}
