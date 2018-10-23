package dtls

type cipherSuiteID uint16

// Taken from https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
const (
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipherSuiteID = 0xc02b
) // A cipherSuite is a specific combination of key agreement, cipher and MAC
// function. All cipher suites currently assume RSA key agreement.
type cipherSuite struct {
	id cipherSuiteID
}

var cipherSuites = map[cipherSuiteID]*cipherSuite{
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {id: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
}

var defaultCipherSuites = []*cipherSuite{
	cipherSuites[TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
}
