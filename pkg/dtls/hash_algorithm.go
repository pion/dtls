package dtls

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
type hashAlgorithm uint16

const (
	hashAlgorithmSHA1   hashAlgorithm = 2
	hashAlgorithmSHA256 hashAlgorithm = 4
)

var hashAlgorithms = map[hashAlgorithm]bool{
	hashAlgorithmSHA1:   true,
	hashAlgorithmSHA256: true,
}
