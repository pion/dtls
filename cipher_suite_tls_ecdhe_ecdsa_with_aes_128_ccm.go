package dtls

func NewCipherSuiteTLSEcdheEcdsaWithAes128Ccm() *CipherSuiteAes128Ccm {
	return NewCipherSuiteAes128Ccm(ClientCertificateTypeECDSASign, TLS_ECDHE_ECDSA_WITH_AES_128_CCM, false, cryptoCCMTagLength)
}
