package dtls

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-10
type ClientCertificateType byte

const (
	ClientCertificateTypeRSASign   ClientCertificateType = 1
	ClientCertificateTypeECDSASign ClientCertificateType = 64
)

func clientCertificateTypes() map[ClientCertificateType]bool {
	return map[ClientCertificateType]bool{
		ClientCertificateTypeRSASign:   true,
		ClientCertificateTypeECDSASign: true,
	}
}
