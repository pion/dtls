package dtls

import (
	"crypto"
	"crypto/x509"
)

// Config is used to configure a DTLS client or server.
// After a Config is passed to a DTLS function it must not be modified.
type Config struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
}
