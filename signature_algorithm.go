package dtls

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
type signatureAlgorithm uint16

const (
	signatureAlgorithmAnonymous signatureAlgorithm = 0
	signatureAlgorithmRSA       signatureAlgorithm = 1
	signatureAlgorithmECDSA     signatureAlgorithm = 3
	signatureAlgorithmEd25519   signatureAlgorithm = 7
)

func signatureAlgorithms() map[signatureAlgorithm]bool {
	return map[signatureAlgorithm]bool{
		signatureAlgorithmAnonymous: true,
		signatureAlgorithmRSA:       true,
		signatureAlgorithmECDSA:     true,
		signatureAlgorithmEd25519:   true,
	}
}
