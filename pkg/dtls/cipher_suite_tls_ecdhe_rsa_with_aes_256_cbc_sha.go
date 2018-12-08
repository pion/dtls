package dtls

type cipherSuiteTLSEcdheRsaWithAes256CbcSha struct {
	cipherSuiteTLSEcdheEcdsaWithAes256CbcSha
}

func (c cipherSuiteTLSEcdheRsaWithAes256CbcSha) certificateType() clientCertificateType {
	return clientCertificateTypeRSASign
}

func (c cipherSuiteTLSEcdheRsaWithAes256CbcSha) ID() cipherSuiteID {
	return 0x0035
}
