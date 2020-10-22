package dtls

type CipherSuiteTLSEcdheRsaWithAes256CbcSha struct {
	CipherSuiteTLSEcdheEcdsaWithAes256CbcSha
}

func (c *CipherSuiteTLSEcdheRsaWithAes256CbcSha) CertificateType() ClientCertificateType {
	return ClientCertificateTypeRSASign
}

func (c *CipherSuiteTLSEcdheRsaWithAes256CbcSha) ID() CipherSuiteID {
	return TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
}

func (c *CipherSuiteTLSEcdheRsaWithAes256CbcSha) String() string {
	return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
}
