package dtls

type CipherSuiteTLSEcdheRsaWithAes128GcmSha256 struct {
	CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256
}

func (c *CipherSuiteTLSEcdheRsaWithAes128GcmSha256) CertificateType() ClientCertificateType {
	return ClientCertificateTypeRSASign
}

func (c *CipherSuiteTLSEcdheRsaWithAes128GcmSha256) ID() CipherSuiteID {
	return TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
}

func (c *CipherSuiteTLSEcdheRsaWithAes128GcmSha256) String() string {
	return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
}
