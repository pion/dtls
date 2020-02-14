package dtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/pion/logging"
)

// Config is used to configure a DTLS client or server.
// After a Config is passed to a DTLS function it must not be modified.
type Config struct {
	// Certificates contains certificate chain to present to the other side of the connection.
	// Server MUST set this if PSK is non-nil
	// client SHOULD sets this so CertificateRequests can be handled if PSK is non-nil
	// TODO: add support to use more certificates then one.
	Certificates []tls.Certificate

	// CipherSuites is a list of supported cipher suites.
	// If CipherSuites is nil, a default list is used
	CipherSuites []CipherSuiteID

	// SRTPProtectionProfiles are the supported protection profiles
	// Clients will send this via use_srtp and assert that the server properly responds
	// Servers will assert that clients send one of these profiles and will respond as needed
	SRTPProtectionProfiles []SRTPProtectionProfile

	// ClientAuth determines the server's policy for
	// TLS Client Authentication. The default is NoClientCert.
	ClientAuth ClientAuthType

	// RequireExtendedMasterSecret determines if the "Extended Master Secret" extension
	// should be disabled, requested, or required (default requested).
	ExtendedMasterSecret ExtendedMasterSecretType

	// FlightInterval controls how often we send outbound handshake messages
	// defaults to time.Second
	FlightInterval time.Duration

	// PSK sets the pre-shared key used by this DTLS connection
	// If PSK is non-nil only PSK CipherSuites will be used
	PSK             PSKCallback
	PSKIdentityHint []byte

	// InsecureSkipVerify controls whether a client verifies the
	// server's certificate chain and host name.
	// If InsecureSkipVerify is true, TLS accepts any certificate
	// presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	InsecureSkipVerify bool

	// VerifyPeerCertificate, if not nil, is called after normal
	// certificate verification by either a client or server. It
	// receives the certificate provided by the peer and also a flag
	// that tells if normal verification has succeedded. If it returns a
	// non-nil error, the handshake is aborted and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. If normal verification is disabled by
	// setting InsecureSkipVerify, or (for a server) when ClientAuth is
	// RequestClientCert or RequireAnyClientCert, then this callback will
	// be considered but the verifiedChains will always be nil.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// RootCAs defines the set of root certificate authorities
	// that one peer uses when verifying the other peer's certificates.
	// If RootCAs is nil, TLS uses the host's root CA set.
	RootCAs *x509.CertPool

	// ClientCAs defines the set of root certificate authorities
	// that servers use if required to verify a client certificate
	// by the policy in ClientAuth.
	ClientCAs *x509.CertPool

	// ServerName is used to verify the hostname on the returned
	// certificates unless InsecureSkipVerify is given.
	ServerName string

	LoggerFactory logging.LoggerFactory

	// ConnectContextMaker is a function to make a context used in Dial(),
	// Client(), Server(), and Accept(). If nil, the default ConnectContextMaker
	// is used. It can be implemented as following.
	//
	// 	func ConnectContextMaker() (context.Context, func()) {
	// 		return context.WithTimeout(context.Background(), 30*time.Second)
	// 	}
	ConnectContextMaker func() (context.Context, func())

	// MTU is the length at which handshake messages will be fragmented to
	// fit within the maximum transmission unit (default is 1200 bytes)
	MTU int
}

func defaultConnectContextMaker() (context.Context, func()) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func (c *Config) connectContextMaker() (context.Context, func()) {
	if c.ConnectContextMaker == nil {
		return defaultConnectContextMaker()
	}
	return c.ConnectContextMaker()
}

const defaultMTU = 1200 // bytes

// PSKCallback is called once we have the remote's PSKIdentityHint.
// If the remote provided none it will be nil
type PSKCallback func([]byte) ([]byte, error)

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

// ClientAuthType enums
const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

// ExtendedMasterSecretType declares the policy the client and server
// will follow for the Extended Master Secret extension
type ExtendedMasterSecretType int

// ExtendedMasterSecretType enums
const (
	RequestExtendedMasterSecret ExtendedMasterSecretType = iota
	RequireExtendedMasterSecret
	DisableExtendedMasterSecret
)

func validateConfig(config *Config) error {
	switch {
	case config == nil:
		return errNoConfigProvided
	case len(config.Certificates) > 0 && config.PSK != nil:
		return errPSKAndCertificate
	case config.PSKIdentityHint != nil && config.PSK == nil:
		return errIdentityNoPSK
	}

	for _, cert := range config.Certificates {
		if cert.Certificate == nil {
			return errInvalidCertificate
		}
		if cert.PrivateKey != nil {
			switch cert.PrivateKey.(type) {
			case ed25519.PrivateKey:
			case *ecdsa.PrivateKey:
			default:
				return errInvalidPrivateKey
			}
		}
	}

	_, err := parseCipherSuites(config.CipherSuites, config.PSK == nil, config.PSK != nil)
	return err
}
