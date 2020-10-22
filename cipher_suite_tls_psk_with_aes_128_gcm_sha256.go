package dtls

type CipherSuiteTLSPskWithAes128GcmSha256 struct {
	CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256
}

func (c *CipherSuiteTLSPskWithAes128GcmSha256) CertificateType() ClientCertificateType {
	return ClientCertificateType(0)
}

func (c *CipherSuiteTLSPskWithAes128GcmSha256) ID() CipherSuiteID {
	return TLS_PSK_WITH_AES_128_GCM_SHA256
}

func (c *CipherSuiteTLSPskWithAes128GcmSha256) String() string {
	return "TLS_PSK_WITH_AES_128_GCM_SHA256"
}

func (c *CipherSuiteTLSPskWithAes128GcmSha256) IsPSK() bool {
	return true
}

func (c *CipherSuiteTLSPskWithAes128GcmSha256) IsAnon() bool {
	return false
}
