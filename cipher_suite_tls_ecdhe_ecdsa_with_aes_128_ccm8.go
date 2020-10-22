package dtls

func NewCipherSuiteTLSEcdheEcdsaWithAes128Ccm8() *CipherSuiteAes128Ccm {
	return NewCipherSuiteAes128Ccm(ClientCertificateTypeECDSASign, TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, false, cryptoCCM8TagLength)
}
