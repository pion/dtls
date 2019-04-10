package dtls

type cipherSuiteTLSEcdheRsaWithAes128GcmSha256 struct {
	cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256
}

func (c cipherSuiteTLSEcdheRsaWithAes128GcmSha256) certificateType() clientCertificateType {
	return clientCertificateTypeRSASign
}

func (c cipherSuiteTLSEcdheRsaWithAes128GcmSha256) ID() cipherSuiteID {
	return 0xc02f
}

func (c cipherSuiteTLSEcdheRsaWithAes128GcmSha256) String() string {
	return "TLSEcdheRsaWithAes128GcmSha256"
}
