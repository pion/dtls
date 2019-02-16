package dtls

import (
	"crypto"
	"crypto/x509"
)

// Config is used to configure a DTLS client or server.
// After a Config is passed to a DTLS function it must not be modified.
type Config struct {
	// Certificates contains certificate chain to present to
	// the other side of the connection. Server MUST set this,
	// client SHOULD sets this so CertificateRequests
	// can be handled
	Certificate *x509.Certificate

	// PrivateKey contains matching private key for the certificate
	// only ECDSA is supported
	PrivateKey crypto.PrivateKey

	// SRTPProtectionProfiles are the supported protection profiles
	// Clients will send this via use_srtp and assert that the server properly responds
	// Servers will assert that clients send one of these profiles and will respond as needed
	SRTPProtectionProfiles []SRTPProtectionProfile

	// ClientAuth determines the server's policy for
	// TLS Client Authentication. The default is NoClientCert.
	ClientAuth ClientAuthType
}

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

// ClientAuthType enums
const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
)
