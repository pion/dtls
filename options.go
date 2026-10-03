// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/pion/dtls/v4/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsnet "github.com/pion/dtls/v4/internal/net"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/internal/util"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/logging"
)

// ServerOption configures a DTLS server.
type ServerOption interface {
	applyServer(*dtlsConfig) error
}

// ClientOption configures a DTLS client.
type ClientOption interface {
	applyClient(*dtlsConfig) error
}

// Option is an option that can be used with both client and server.
// This is used for options that apply to both sides of a connection,
// such as in the Resume function where the side is determined at runtime.
type Option interface {
	ServerOption
	ClientOption
}

type dtlsConfig struct {
	Certificates                  []tls.Certificate
	CipherSuites                  []cryptosuite.ID
	SignatureSchemes              []tls.SignatureScheme
	CertificateSignatureSchemes   []tls.SignatureScheme
	SRTPProtectionProfiles        []SRTPProtectionProfile
	SRTPMasterKeyIdentifier       []byte
	ClientAuth                    ClientAuthType
	ExtendedMasterSecret          ExtendedMasterSecretType
	FlightInterval                time.Duration
	DisableRetransmitBackoff      bool
	InsecureSkipVerify            bool
	InsecureHashes                bool
	VerifyPeerCertificate         func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	RootCAs                       *x509.CertPool
	ClientCAs                     *x509.CertPool
	ServerName                    string
	LoggerFactory                 logging.LoggerFactory
	MTU                           int
	ReceiveBufferSize             int
	ReplayProtectionWindow        int
	KeyLogWriter                  io.Writer
	SupportedProtocols            []string
	EllipticCurves                []elliptic.Curve
	InsecureSkipVerifyHello       bool
	ReceiveCIDLength              int
	ConnectionIDGenerator         func() []byte
	CIDPathMigrationPolicy        cidPathMigrationPolicy
	PaddingLengthGenerator        func(uint) uint
	HelloRandomBytesGenerator     func() [handshake.RandomBytesLength]byte
	ClientHelloMessageHook        func(handshake.MessageClientHello) handshake.Message
	ServerHelloMessageHook        func(handshake.MessageServerHello) handshake.Message
	CertificateRequestMessageHook func(handshake.MessageCertificateRequest) handshake.Message
	OnConnectionAttempt           func(net.Addr) error
	MinVersion                    protocol.Version
	MaxVersion                    protocol.Version

	customCipherSuites   func() []cryptosuite.Suite
	pskClient            PSKClientCallback
	pskServer            PSKServerCallback
	pskIdentityLimit     int
	isClient             bool
	verifyConnection     func(*State) error
	sessionStore         SessionStore
	getCertificate       func(*ClientHelloInfo) (*tls.Certificate, error)
	getClientCertificate func(*CertificateRequestInfo) (*tls.Certificate, error)
}

func buildConfig(opts ...Option) (*dtlsConfig, error) {
	return applyOptions(false, opts, Option.applyServer)
}

func buildServerConfig(opts ...ServerOption) (*dtlsConfig, error) {
	return applyOptions(false, opts, ServerOption.applyServer)
}

func buildClientConfig(opts ...ClientOption) (*dtlsConfig, error) {
	return applyOptions(true, opts, ClientOption.applyClient)
}

func applyOptions[T any](isClient bool, opts []T, apply func(T, *dtlsConfig) error) (*dtlsConfig, error) {
	cfg := &dtlsConfig{
		isClient:               isClient,
		ExtendedMasterSecret:   RequestExtendedMasterSecret,
		FlightInterval:         time.Second,
		MTU:                    defaultMTU,
		ReceiveBufferSize:      defaultReceiveBufferSize,
		ReplayProtectionWindow: defaultReplayProtectionWindow,
		PaddingLengthGenerator: func(uint) uint { return 0 },
	}
	for _, opt := range opts {
		if err := apply(opt, cfg); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// sharedOption wraps an apply function that works for both client and server.
// This eliminates code duplication for options that behave identically on both sides.
type sharedOption func(*dtlsConfig) error

func (o sharedOption) applyServer(c *dtlsConfig) error { return o(c) }
func (o sharedOption) applyClient(c *dtlsConfig) error { return o(c) }

// valueOption assigns a value only after its validation succeeds.
func valueOption[T any](field func(*dtlsConfig) *T, value T, errs ...error) sharedOption {
	return func(c *dtlsConfig) error {
		for _, err := range errs {
			if err != nil {
				return err
			}
		}
		*field(c) = value

		return nil
	}
}

func optionError(invalid bool, err error) error {
	if invalid {
		return err
	}

	return nil
}

// sliceOption copies each slice when applied, so configurations do not share it.
func sliceOption[T any](field func(*dtlsConfig) *[]T, values []T, emptyErr error) sharedOption {
	return func(c *dtlsConfig) error {
		if len(values) == 0 {
			return emptyErr
		}
		*field(c) = slices.Clone(values)

		return nil
	}
}

// WithCertificates sets the certificate chain to present to the other side of the connection.
// For functional options, an explicitly empty slice is not allowed.
func WithCertificates(certs ...tls.Certificate) Option {
	return sliceOption(func(c *dtlsConfig) *[]tls.Certificate { return &c.Certificates }, certs, dtlserrors.ErrEmptyCertificates)
}

// WithCipherSuites sets the supported cipher suites.
// For functional options, an explicitly empty slice is not allowed.
func WithCipherSuites(suites ...cryptosuite.ID) Option {
	return sliceOption(func(c *dtlsConfig) *[]cryptosuite.ID { return &c.CipherSuites }, suites, dtlserrors.ErrEmptyCipherSuites)
}

// WithCustomCipherSuites sets the custom cipher suites provider.
// Returns an error if the provider is nil.
func WithCustomCipherSuites(fn func() []cryptosuite.Suite) Option {
	return valueOption(func(c *dtlsConfig) *func() []cryptosuite.Suite { return &c.customCipherSuites }, fn, optionError(fn == nil, dtlserrors.ErrNilCustomCipherSuites))
}

// WithSignatureSchemes sets the signature schemes.
// For functional options, an explicitly empty slice is not allowed.
func WithSignatureSchemes(schemes ...tls.SignatureScheme) Option {
	return sliceOption(func(c *dtlsConfig) *[]tls.SignatureScheme { return &c.SignatureSchemes }, schemes, dtlserrors.ErrEmptySignatureSchemes)
}

// WithCertificateSignatureSchemes sets the signature and hash schemes that may be used
// in digital signatures for X.509 certificates. If not set, the signature_algorithms_cert
// extension is not sent, and SignatureSchemes is used for both handshake signatures and
// certificate chain validation, as specified in RFC 8446 Section 4.2.3.
// For functional options, an explicitly empty slice is not allowed.
func WithCertificateSignatureSchemes(schemes ...tls.SignatureScheme) Option {
	return sliceOption(func(c *dtlsConfig) *[]tls.SignatureScheme { return &c.CertificateSignatureSchemes }, schemes, dtlserrors.ErrEmptyCertificateSignatureSchemes)
}

// WithSRTPProtectionProfiles sets the SRTP protection profiles.
// For functional options, an explicitly empty slice is not allowed.
func WithSRTPProtectionProfiles(profiles ...SRTPProtectionProfile) Option {
	return sliceOption(func(c *dtlsConfig) *[]SRTPProtectionProfile { return &c.SRTPProtectionProfiles }, profiles, dtlserrors.ErrEmptySRTPProtectionProfiles)
}

// WithSRTPMasterKeyIdentifier sets the SRTP master key identifier.
func WithSRTPMasterKeyIdentifier(identifier []byte) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.SRTPMasterKeyIdentifier = slices.Clone(identifier)

		return nil
	})
}

// WithExtendedMasterSecret sets the extended master secret policy.
// Returns an error if the type is invalid.
func WithExtendedMasterSecret(ems ExtendedMasterSecretType) Option {
	return valueOption(func(c *dtlsConfig) *ExtendedMasterSecretType { return &c.ExtendedMasterSecret }, ems, optionError(ems < RequestExtendedMasterSecret || ems > DisableExtendedMasterSecret, dtlserrors.ErrInvalidExtendedMasterSecretType))
}

// WithFlightInterval sets the flight interval for handshake messages.
// Returns an error if the interval is not positive.
func WithFlightInterval(interval time.Duration) Option {
	return valueOption(func(c *dtlsConfig) *time.Duration { return &c.FlightInterval }, interval, optionError(interval <= 0, dtlserrors.ErrInvalidFlightInterval))
}

// WithDisableRetransmitBackoff disables retransmit backoff.
func WithDisableRetransmitBackoff(disable bool) Option {
	return valueOption(func(c *dtlsConfig) *bool { return &c.DisableRetransmitBackoff }, disable)
}

// PSK is an external pre-shared key and its identity.
type PSK struct {
	Identity []byte
	Key      []byte
	// Hash is the DTLS 1.3 PSK hash: crypto.SHA256 or crypto.SHA384.
	// Zero defaults to crypto.SHA256. It does not select the DTLS 1.2 cipher hash.
	Hash crypto.Hash
}

// PSKClientCallback supplies the client's PSKs once per connection.
// DTLS 1.3 offers all entries in order and DTLS 1.2 uses only the first.
// An error aborts the handshake. The callback does not receive a DTLS 1.2 server hint.
type PSKClientCallback func() ([]PSK, error)

// PSKServerCallback selects a PSK from the client's offered identities.
// The returned PSK must include an offered Identity, its Key, and Hash.
// Return nil, nil if none match. An error aborts the handshake.
// DTLS 1.2 supplies one identity. DTLS 1.3 may call again after a retry.
type PSKServerCallback func(identities [][]byte) (*PSK, error)

// PSKOption configures PSK-specific settings in WithPSK.
type PSKOption interface {
	applyPSK(*dtlsConfig) error
}

type pskOption func(*dtlsConfig) error

func (o pskOption) applyPSK(c *dtlsConfig) error { return o(c) }

// WithPSKIdentityLimit sets the maximum number of identities accepted by the server.
// The limit must be positive. Offers exceeding it are rejected before the server callback.
func WithPSKIdentityLimit(limit int) PSKOption {
	return pskOption(valueOption(func(c *dtlsConfig) *int { return &c.pskIdentityLimit }, limit, optionError(limit <= 0, dtlserrors.ErrInvalidPSKIdentityLimit)))
}

// WithPSK sets the client offer and server lookup callbacks.
// The server accepts at most 32 identities per offer unless overridden by opts.
// A nil callback disables PSK for that role. Both callbacks may be nil.
func WithPSK(client PSKClientCallback, server PSKServerCallback, opts ...PSKOption) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.pskIdentityLimit = 32
		for _, opt := range opts {
			if err := opt.applyPSK(c); err != nil {
				return err
			}
		}
		c.pskClient, c.pskServer = client, server

		return nil
	})
}

// WithInsecureSkipVerify skips certificate verification.
// This should only be used for testing.
func WithInsecureSkipVerify(skip bool) Option {
	return valueOption(func(c *dtlsConfig) *bool { return &c.InsecureSkipVerify }, skip)
}

// WithInsecureHashes allows the use of insecure hash algorithms.
func WithInsecureHashes(allow bool) Option {
	return valueOption(func(c *dtlsConfig) *bool { return &c.InsecureHashes }, allow)
}

// WithVerifyPeerCertificate sets the peer certificate verification callback.
// Returns an error if the callback is nil.
func WithVerifyPeerCertificate(fn func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error) Option {
	return valueOption(func(c *dtlsConfig) *func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return &c.VerifyPeerCertificate
	}, fn, optionError(fn == nil, dtlserrors.ErrNilVerifyPeerCertificate))
}

// WithVerifyConnection sets the connection verification callback.
// Returns an error if the callback is nil.
func WithVerifyConnection(fn func(*State) error) Option {
	return valueOption(func(c *dtlsConfig) *func(*State) error { return &c.verifyConnection }, fn, optionError(fn == nil, dtlserrors.ErrNilVerifyConnection))
}

// WithRootCAs sets the root certificate authorities.
func WithRootCAs(pool *x509.CertPool) Option {
	return valueOption(func(c *dtlsConfig) **x509.CertPool { return &c.RootCAs }, pool)
}

// WithServerName sets the server name for certificate verification.
func WithServerName(name string) Option {
	return valueOption(func(c *dtlsConfig) *string { return &c.ServerName }, name)
}

// WithLoggerFactory sets the logger factory for creating loggers.
func WithLoggerFactory(factory logging.LoggerFactory) Option {
	return valueOption(func(c *dtlsConfig) *logging.LoggerFactory { return &c.LoggerFactory }, factory)
}

// WithMTU sets the size used for handshake fragmentation and record packing.
// The default is 1200 bytes.
func WithMTU(mtu int) Option {
	return valueOption(func(c *dtlsConfig) *int { return &c.MTU }, mtu, optionError(mtu < minMTU || mtu > dtlsnet.MaxInboundDatagramSize, dtlserrors.ErrInvalidMTU))
}

// WithReceiveBufferSize sets the size of the in-memory buffers used to read
// incoming datagrams. A datagram larger than this size cannot be received —
// depending on the transport it is truncated or rejected — so it must be at
// least as large as the largest datagram the peer may send. The default is
// 8192 bytes.
//
// This does not change the kernel socket receive buffer (SO_RCVBUF); use
// net.UDPConn.SetReadBuffer for that.
// Returns an error if the buffer size is not positive or greater than the 65535.
func WithReceiveBufferSize(size int) Option {
	return valueOption(func(c *dtlsConfig) *int { return &c.ReceiveBufferSize }, size, optionError(size < minReceiveBufferSize || size > dtlsnet.MaxInboundDatagramSize, dtlserrors.ErrInvalidReceiveBufferSize))
}

// WithReplayProtectionWindow sets the replay protection window size.
// Returns an error if the window size is negative.
func WithReplayProtectionWindow(window int) Option {
	return valueOption(func(c *dtlsConfig) *int { return &c.ReplayProtectionWindow }, window, optionError(window < 0, dtlserrors.ErrInvalidReplayProtectionWindow))
}

// WithKeyLogWriter sets the key log writer for debugging.
// Use of KeyLogWriter compromises security and should only be used for debugging.
func WithKeyLogWriter(writer io.Writer) Option {
	return valueOption(func(c *dtlsConfig) *io.Writer { return &c.KeyLogWriter }, writer)
}

// WithSessionStore sets the session store for resumption.
func WithSessionStore(store SessionStore) Option {
	return valueOption(func(c *dtlsConfig) *SessionStore { return &c.sessionStore }, store)
}

// WithSupportedProtocols sets the supported application protocols for ALPN.
// For functional options, an explicitly empty slice is not allowed.
func WithSupportedProtocols(protocols ...string) Option {
	return sliceOption(func(c *dtlsConfig) *[]string { return &c.SupportedProtocols }, protocols, dtlserrors.ErrEmptySupportedProtocols)
}

// WithEllipticCurves sets the elliptic curves.
// For functional options, an explicitly empty slice is not allowed.
func WithEllipticCurves(curves ...elliptic.Curve) Option {
	return sliceOption(func(c *dtlsConfig) *[]elliptic.Curve { return &c.EllipticCurves }, curves, dtlserrors.ErrEmptyEllipticCurves)
}

// WithGetClientCertificate sets the client certificate getter callback.
// Returns an error if the callback is nil.
func WithGetClientCertificate(fn func(*CertificateRequestInfo) (*tls.Certificate, error)) Option {
	return valueOption(func(c *dtlsConfig) *func(*CertificateRequestInfo) (*tls.Certificate, error) {
		return &c.getClientCertificate
	}, fn, optionError(fn == nil, dtlserrors.ErrNilGetClientCertificate))
}

type cidPathMigrationPolicy uint8

const (
	// CIDPathMigrationReject retains the current peer address and logs CID path
	// migration attempts. This is required when no reachability validation
	// strategy is configured
	// https://datatracker.ietf.org/doc/html/rfc9146#section-6
	// https://datatracker.ietf.org/doc/html/rfc9147#section-11
	CIDPathMigrationReject cidPathMigrationPolicy = iota
	// CIDPathMigrationUnsafe immediately accepts an authenticated CID path.
	// It is intended only for transports, such as ICE, that validate paths
	// outside DTLS.
	CIDPathMigrationUnsafe
	// CIDPathMigrationRRC validates a CID path with return routability checks
	// before accepting it. RRC is advertised and negotiated only in this mode.
	// https://datatracker.ietf.org/doc/html/rfc9853
	CIDPathMigrationRRC
)

// WithConnectionID enables connection IDs and configures how authenticated
// connection ID records may change the peer address. The generator must always
// return IDs of the same length, at most 255 bytes.
// A zero length advertises support for sending a peer's CID without asking the
// peer to send one in return.
func WithConnectionID(generator func() []byte, policy cidPathMigrationPolicy) Option {
	var generatorMu sync.Mutex

	return sharedOption(func(config *dtlsConfig) error {
		if generator == nil {
			return dtlserrors.ErrNilConnectionIDGenerator
		}
		config.ConnectionIDGenerator = func() []byte {
			generatorMu.Lock()
			defer generatorMu.Unlock()

			return bytes.Clone(generator())
		}
		config.ReceiveCIDLength = len(config.ConnectionIDGenerator())
		if config.ReceiveCIDLength > math.MaxUint8 {
			return fmt.Errorf("%w: generator returned %d bytes, maximum is %d", dtlserrors.ErrInvalidConnectionIDLength, config.ReceiveCIDLength, math.MaxUint8)
		}
		config.CIDPathMigrationPolicy = policy

		return nil
	})
}

// WithPaddingLengthGenerator sets the padding length generator.
// Returns an error if the generator is nil.
func WithPaddingLengthGenerator(fn func(uint) uint) Option {
	return valueOption(func(c *dtlsConfig) *func(uint) uint { return &c.PaddingLengthGenerator }, fn, optionError(fn == nil, dtlserrors.ErrNilPaddingLengthGenerator))
}

// WithHelloRandomBytesGenerator sets the hello random bytes generator.
// Returns an error if the generator is nil.
func WithHelloRandomBytesGenerator(fn func() [handshake.RandomBytesLength]byte) Option {
	return valueOption(func(c *dtlsConfig) *func() [handshake.RandomBytesLength]byte { return &c.HelloRandomBytesGenerator }, fn, optionError(fn == nil, dtlserrors.ErrNilHelloRandomBytesGenerator))
}

// WithClientHelloMessageHook sets the client hello message hook.
// Returns an error if the hook is nil.
func WithClientHelloMessageHook(fn func(handshake.MessageClientHello) handshake.Message) Option {
	return valueOption(func(c *dtlsConfig) *func(handshake.MessageClientHello) handshake.Message {
		return &c.ClientHelloMessageHook
	}, fn, optionError(fn == nil, dtlserrors.ErrNilClientHelloMessageHook))
}

// WithMinVersion sets the minimum TLS version that is acceptable.
// By default, DTLS 1.2 is currently used as the minimum as it's the only supported version.
func WithMinVersion(version protocol.Version) Option {
	return valueOption(func(c *dtlsConfig) *protocol.Version { return &c.MinVersion }, version,
		optionError(version != protocol.Version1_2 && version != protocol.Version1_3, dtlserrors.ErrUnsupportedProtocolVersion))
}

// WithMaxVersion sets the maximum TLS version that is acceptable.
// By default, DTLS 1.2 is currently used as the maximum.
func WithMaxVersion(version protocol.Version) Option {
	return valueOption(func(c *dtlsConfig) *protocol.Version { return &c.MaxVersion }, version,
		optionError(version != protocol.Version1_2 && version != protocol.Version1_3, dtlserrors.ErrUnsupportedProtocolVersion))
}

// serverOnlyOption wraps an apply function for server-only options.
type serverOnlyOption func(*dtlsConfig) error

func (o serverOnlyOption) applyServer(c *dtlsConfig) error { return o(c) }

// WithClientAuth sets the client authentication policy.
// Returns an error if the type is invalid.
// This option is only applicable to servers.
func WithClientAuth(auth ClientAuthType) ServerOption {
	return serverOnlyOption(valueOption(func(c *dtlsConfig) *ClientAuthType { return &c.ClientAuth }, auth, optionError(auth < NoClientCert || auth > RequireAndVerifyClientCert, dtlserrors.ErrInvalidClientAuthType)))
}

// WithClientCAs sets the client certificate authorities.
// This option is only applicable to servers.
func WithClientCAs(pool *x509.CertPool) ServerOption {
	return serverOnlyOption(valueOption(func(c *dtlsConfig) **x509.CertPool { return &c.ClientCAs }, pool))
}

// WithGetCertificate sets the certificate getter callback.
// Returns an error if the callback is nil.
// This option is only applicable to servers.
func WithGetCertificate(fn func(*ClientHelloInfo) (*tls.Certificate, error)) ServerOption {
	return serverOnlyOption(valueOption(func(c *dtlsConfig) *func(*ClientHelloInfo) (*tls.Certificate, error) { return &c.getCertificate }, fn, optionError(fn == nil, dtlserrors.ErrNilGetCertificate)))
}

// WithInsecureSkipVerifyHello skips hello verify phase on the server.
// This has implication on DoS attack resistance.
// This option is only applicable to servers.
func WithInsecureSkipVerifyHello(skip bool) ServerOption {
	return serverOnlyOption(valueOption(func(c *dtlsConfig) *bool { return &c.InsecureSkipVerifyHello }, skip))
}

// WithServerHelloMessageHook sets the server hello message hook.
// Returns an error if the hook is nil.
// This option is only applicable to servers.
func WithServerHelloMessageHook(fn func(handshake.MessageServerHello) handshake.Message) ServerOption {
	return serverOnlyOption(valueOption(func(c *dtlsConfig) *func(handshake.MessageServerHello) handshake.Message {
		return &c.ServerHelloMessageHook
	}, fn, optionError(fn == nil, dtlserrors.ErrNilServerHelloMessageHook)))
}

// WithCertificateRequestMessageHook sets the certificate request message hook.
// Returns an error if the hook is nil.
// This option is only applicable to servers.
func WithCertificateRequestMessageHook(fn func(handshake.MessageCertificateRequest) handshake.Message) ServerOption {
	return serverOnlyOption(valueOption(func(c *dtlsConfig) *func(handshake.MessageCertificateRequest) handshake.Message {
		return &c.CertificateRequestMessageHook
	}, fn, optionError(fn == nil, dtlserrors.ErrNilCertificateRequestMessageHook)))
}

// WithOnConnectionAttempt sets the connection attempt callback.
// Returns an error if the callback is nil.
// This option is only applicable to servers.
func WithOnConnectionAttempt(fn func(net.Addr) error) ServerOption {
	return serverOnlyOption(valueOption(func(c *dtlsConfig) *func(net.Addr) error { return &c.OnConnectionAttempt }, fn, optionError(fn == nil, dtlserrors.ErrNilOnConnectionAttempt)))
}

const (
	minMTU     = 1
	defaultMTU = 1200 // bytes

	minReceiveBufferSize = 1
)

var defaultCurves = []elliptic.Curve{ //nolint:gochecknoglobals
	elliptic.X25519MLKEM768,
	elliptic.X25519,
	elliptic.P256,
	elliptic.P384,
}

type connConfigValues struct {
	logger                      logging.LeveledLogger
	maximumTransmissionUnit     int
	receiveBufferSize           int
	paddingLengthGenerator      func(uint) uint
	replayProtectionWindow      int
	initialRetransmitInterval   time.Duration
	minVersion                  protocol.Version
	maxVersion                  protocol.Version
	cipherSuites                []dtlsconfig.CipherSuite
	signatureSchemes            []signaturehash.Algorithm
	certificateSignatureSchemes []signaturehash.Algorithm
	ellipticCurves              []elliptic.Curve
	serverName                  string
	cidPathMigrationPolicy      cidPathMigrationPolicy
}

func newConnConfigValues(config *dtlsConfig) (connConfigValues, error) {
	minVersion, maxVersion, err := effectiveProtocolVersionRange(config)
	if err != nil {
		return connConfigValues{}, err
	}

	cipherSuites, err := selectCipherSuites(config.CipherSuites, config.customCipherSuites, config.includeCertificateSuites(), config.pskEnabled(), minVersion, maxVersion)
	if err != nil {
		return connConfigValues{}, err
	}

	signatureSchemes, certSignatureSchemes, err := parseConnSignatureSchemes(config)
	if err != nil {
		return connConfigValues{}, err
	}

	return connConfigValues{
		logger:                      newConnLogger(config),
		maximumTransmissionUnit:     config.MTU,
		receiveBufferSize:           config.ReceiveBufferSize,
		paddingLengthGenerator:      config.PaddingLengthGenerator,
		replayProtectionWindow:      effectiveReplayProtectionWindow(config.ReplayProtectionWindow),
		initialRetransmitInterval:   config.FlightInterval,
		minVersion:                  minVersion,
		maxVersion:                  maxVersion,
		cipherSuites:                cipherSuites,
		signatureSchemes:            signatureSchemes,
		certificateSignatureSchemes: certSignatureSchemes,
		ellipticCurves:              effectiveEllipticCurves(config.EllipticCurves),
		serverName:                  effectiveServerName(config.ServerName),
		cidPathMigrationPolicy:      config.CIDPathMigrationPolicy,
	}, nil
}

func parseConnSignatureSchemes(
	config *dtlsConfig,
) ([]signaturehash.Algorithm, []signaturehash.Algorithm, error) {
	signatureSchemes, err := signaturehash.ParseSignatureSchemes(config.SignatureSchemes, config.InsecureHashes)
	if err != nil {
		return nil, nil, err
	}

	var certSignatureSchemes []signaturehash.Algorithm
	if len(config.CertificateSignatureSchemes) > 0 {
		certSignatureSchemes, err = signaturehash.ParseSignatureSchemes(config.CertificateSignatureSchemes, config.InsecureHashes)
		if err != nil {
			return nil, nil, err
		}
	}

	return signatureSchemes, certSignatureSchemes, nil
}

func newConnLogger(config *dtlsConfig) logging.LeveledLogger {
	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	return loggerFactory.NewLogger("dtls")
}

func effectiveReplayProtectionWindow(replayProtectionWindow int) int {
	if replayProtectionWindow <= 0 {
		return defaultReplayProtectionWindow
	}

	return replayProtectionWindow
}

func effectiveServerName(serverName string) string {
	// Do not allow the use of an IP address literal as an SNI value.
	// See RFC 6066, Section 3.
	if net.ParseIP(serverName) != nil {
		return ""
	}

	return serverName
}

func effectiveEllipticCurves(curves []elliptic.Curve) []elliptic.Curve {
	if len(curves) == 0 {
		curves = defaultCurves
	}
	if !fips140.Enabled() {
		return curves
	}

	return filterFIPSCurves(curves)
}

func filterFIPSCurves(curves []elliptic.Curve) []elliptic.Curve {
	filtered := make([]elliptic.Curve, 0, len(curves))
	for _, curve := range curves {
		if curve != elliptic.X25519 && curve != elliptic.X25519MLKEM768 {
			filtered = append(filtered, curve)
		}
	}

	return filtered
}

// cipherSuiteFIPSApproved reports whether a suite's cipher comes from the Go FIPS
// module. ChaCha20-Poly1305 and AES-CCM don't, so they're not approved in FIPS
// mode; AES-GCM and AES-CBC are fine.
func cipherSuiteFIPSApproved(id cryptosuite.ID) bool {
	switch id {
	case cryptosuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		cryptosuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		cryptosuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
		cryptosuite.TLS_CHACHA20_POLY1305_SHA256,
		cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		cryptosuite.TLS_PSK_WITH_AES_128_CCM,
		cryptosuite.TLS_PSK_WITH_AES_128_CCM_8,
		cryptosuite.TLS_PSK_WITH_AES_256_CCM_8:
		return false
	default:
		return true
	}
}

func adaptVerifyConnection(verifyConnection func(*State) error) func(dtlsstate.Active) error {
	if verifyConnection == nil {
		return nil
	}

	return func(state dtlsstate.Active) error {
		stateSnapshot, err := generateStateForVerifyConnection(state)
		if err != nil {
			return err
		}

		return verifyConnection(stateSnapshot)
	}
}

func adaptGetCertificate(getCertificate func(*ClientHelloInfo) (*tls.Certificate, error)) func(*dtlsconfig.ClientHelloInfo) (*tls.Certificate, error) {
	if getCertificate == nil {
		return nil
	}

	return func(info *dtlsconfig.ClientHelloInfo) (*tls.Certificate, error) {
		return getCertificate(&ClientHelloInfo{ServerName: info.ServerName, CipherSuites: info.CipherSuites, RandomBytes: info.RandomBytes})
	}
}

func adaptGetClientCertificate(getClientCertificate func(*CertificateRequestInfo) (*tls.Certificate, error)) func(*dtlsconfig.CertificateRequestInfo) (*tls.Certificate, error) {
	if getClientCertificate == nil {
		return nil
	}

	return func(info *dtlsconfig.CertificateRequestInfo) (*tls.Certificate, error) {
		signatureSchemes := make([]tls.SignatureScheme, 0, len(info.SignatureSchemes))
		for _, algorithm := range info.SignatureSchemes {
			raw := algorithm.Marshal()
			signatureSchemes = append(signatureSchemes, tls.SignatureScheme(uint16(raw[0])<<8|uint16(raw[1])))
		}

		return getClientCertificate(&CertificateRequestInfo{CertificateTypes: info.CertificateTypes, AcceptableCAs: info.AcceptableCAs, SignatureSchemes: signatureSchemes})
	}
}

func newHandshakeConfig(config *dtlsConfig, configValues connConfigValues, resumeState *dtlsstate.State) *dtlsconfig.HandshakeConfig {
	handshakeConfig := &dtlsconfig.HandshakeConfig{
		LocalCipherSuites:             configValues.cipherSuites,
		LocalSignatureSchemes:         configValues.signatureSchemes,
		LocalCertSignatureSchemes:     configValues.certificateSignatureSchemes,
		ExtendedMasterSecret:          dtlsconfig.ExtendedMasterSecretType(config.ExtendedMasterSecret),
		LocalSRTPProtectionProfiles:   config.SRTPProtectionProfiles,
		LocalSRTPMasterKeyIdentifier:  config.SRTPMasterKeyIdentifier,
		ServerName:                    configValues.serverName,
		SupportedProtocols:            config.SupportedProtocols,
		ClientAuth:                    dtlsconfig.ClientAuthType(config.ClientAuth),
		LocalCertificates:             config.Certificates,
		InsecureSkipVerify:            config.InsecureSkipVerify,
		VerifyPeerCertificate:         config.VerifyPeerCertificate,
		VerifyConnection:              adaptVerifyConnection(config.verifyConnection),
		HasSessionStore:               config.sessionStore != nil,
		RootCAs:                       config.RootCAs,
		ClientCAs:                     config.ClientCAs,
		InitialRetransmitInterval:     configValues.initialRetransmitInterval,
		DisableRetransmitBackoff:      config.DisableRetransmitBackoff,
		EllipticCurves:                configValues.ellipticCurves,
		InsecureSkipHelloVerify:       config.InsecureSkipVerifyHello,
		ReceiveCIDLength:              config.ReceiveCIDLength,
		ConnectionIDGenerator:         config.ConnectionIDGenerator,
		EnableRRC:                     config.CIDPathMigrationPolicy == CIDPathMigrationRRC,
		HelloRandomBytesGenerator:     config.HelloRandomBytesGenerator,
		Log:                           configValues.logger,
		KeyLogWriter:                  config.KeyLogWriter,
		LocalGetCertificate:           adaptGetCertificate(config.getCertificate),
		LocalGetClientCertificate:     adaptGetClientCertificate(config.getClientCertificate),
		InitialEpoch:                  0,
		ClientHelloMessageHook:        config.ClientHelloMessageHook,
		ServerHelloMessageHook:        config.ServerHelloMessageHook,
		CertificateRequestMessageHook: config.CertificateRequestMessageHook,
		ResumeState:                   resumeState,
		MinVersion:                    configValues.minVersion,
		MaxVersion:                    configValues.maxVersion,
	}
	if config.sessionStore != nil {
		handshakeConfig.GetSession = func(key []byte) (id, secret []byte, err error) {
			session, err := config.sessionStore.Get(key)
			if session.Ticket != nil {
				return nil, nil, err
			}

			return session.ID, session.Secret, err
		}
		handshakeConfig.SetSession = func(key, id, secret []byte) error {
			return config.sessionStore.Set(key, Session{ID: id, Secret: secret})
		}
		handshakeConfig.DelSession = config.sessionStore.Del
		handshakeConfig.SetSessionTicket = func(key, id, secret []byte, ticket dtlsstate.SessionTicket) error {
			return config.sessionStore.Set(key, Session{ID: id, Secret: secret, Ticket: &ticket})
		}
	}

	config.configurePSK(handshakeConfig)

	return handshakeConfig
}

func (c *dtlsConfig) includeCertificateSuites() bool {
	return !c.pskEnabled() || len(c.Certificates) > 0 || c.getCertificate != nil || c.getClientCertificate != nil
}

func (c *dtlsConfig) pskEnabled() bool {
	if c.isClient {
		return c.pskClient != nil
	}

	return c.pskServer != nil
}

// configurePSK adapts the public callbacks to the flight handlers, keeping the
// client's identity and key together for the lifetime of this handshake.
func (c *dtlsConfig) configurePSK(cfg *dtlsconfig.HandshakeConfig) {
	if !c.pskEnabled() {
		return
	}
	if !c.isClient {
		cfg.SelectPSK = c.selectPSK

		return
	}
	var cached []dtlsstate.PSK
	cfg.GetPSKs = func() ([]dtlsstate.PSK, error) {
		if cached != nil {
			return cached, nil
		}
		psks, err := c.pskClient()
		if err != nil {
			return nil, err
		}
		if len(psks) == 0 {
			return nil, dtlserrors.ErrPSKCount
		}
		offered := make([]dtlsstate.PSK, len(psks))
		for i, psk := range psks {
			key, err := psk.cloneKey()
			if err != nil {
				return nil, err
			}
			offered[i] = dtlsstate.PSK{
				Identity: bytes.Clone(psk.Identity), Secret: key, Hash: psk.hash(), External: true,
			}
		}
		cached = offered

		return cached, nil
	}
	cfg.LocalPSKCallback = func([]byte) ([]byte, error) {
		psks, err := cfg.GetPSKs()
		if err != nil {
			return nil, err
		}
		// DTLS 1.2 sends one identity, including an explicitly empty one.
		cfg.LocalPSKIdentityHint = append([]byte{}, psks[0].Identity...)

		return bytes.Clone(psks[0].Secret), nil
	}
}

func (c *dtlsConfig) selectPSK(identities [][]byte) (int, []byte, crypto.Hash, error) {
	if len(identities) > c.pskIdentityLimit {
		return -1, nil, 0, dtlserrors.ErrTooManyPSKIdentities
	}
	psk, err := c.pskServer(util.CloneByteSlices(identities))
	if err != nil || psk == nil {
		return -1, nil, 0, err
	}
	index := slices.IndexFunc(identities, func(identity []byte) bool {
		return bytes.Equal(identity, psk.Identity)
	})
	if index < 0 {
		return -1, nil, 0, dtlserrors.ErrPSKIdentity
	}
	key, err := psk.cloneKey()

	return index, key, psk.hash(), err
}

func (p PSK) hash() crypto.Hash {
	if p.Hash == 0 {
		return crypto.SHA256
	}

	return p.Hash
}

func (p PSK) cloneKey() ([]byte, error) {
	if p.hash() != crypto.SHA256 && p.hash() != crypto.SHA384 {
		return nil, dtlserrors.ErrPSKHash
	}
	if len(p.Key) == 0 {
		return nil, dtlserrors.ErrPSKNotNegotiated
	}

	return bytes.Clone(p.Key), nil
}

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

// ClientAuthType enums.
const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

// ExtendedMasterSecretType declares the policy the client and server
// will follow for the Extended Master Secret extension.
type ExtendedMasterSecretType int

// ExtendedMasterSecretType enums.
const (
	RequestExtendedMasterSecret ExtendedMasterSecretType = iota
	RequireExtendedMasterSecret
	DisableExtendedMasterSecret
)

func validateConfig(config *dtlsConfig) error { //nolint:cyclop
	if config == nil {
		return dtlserrors.ErrNoConfigProvided
	}

	for _, cert := range config.Certificates {
		if cert.Certificate == nil {
			return dtlserrors.ErrInvalidCertificate
		}
		if cert.PrivateKey != nil {
			signer, ok := cert.PrivateKey.(crypto.Signer)
			if !ok {
				return dtlserrors.ErrInvalidPrivateKey
			}
			switch signer.Public().(type) {
			case ed25519.PublicKey:
			case *ecdsa.PublicKey:
			case *rsa.PublicKey:
			default:
				return dtlserrors.ErrInvalidPrivateKey
			}
		}
	}

	minVersion, maxVersion, err := effectiveProtocolVersionRange(config)
	if err != nil {
		return err
	}

	_, err = selectCipherSuites(config.CipherSuites, config.customCipherSuites, config.includeCertificateSuites(), config.pskEnabled(), minVersion, maxVersion)

	return err
}

func defaultCipherSuitesForVersion(version protocol.Version) []cryptosuite.Suite {
	var ids []cryptosuite.ID
	switch version {
	case protocol.Version1_3:
		ids = []cryptosuite.ID{cryptosuite.TLS_AES_128_GCM_SHA256, cryptosuite.TLS_AES_256_GCM_SHA384, cryptosuite.TLS_CHACHA20_POLY1305_SHA256}
	case protocol.Version1_2:
		ids = []cryptosuite.ID{
			cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			cryptosuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			cryptosuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			cryptosuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			cryptosuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}
	case protocol.Version1_0:
		return nil
	}

	suites := make([]cryptosuite.Suite, len(ids))
	for i, id := range ids {
		suites[i] = ciphersuite.ForID(id)
	}

	return suites
}

func filterCipherSuitesForVersion(
	cipherSuites []cryptosuite.Suite,
	version protocol.Version,
) []cryptosuite.Suite {
	return slices.DeleteFunc(slices.Clone(cipherSuites), func(suite cryptosuite.Suite) bool { return !suite.Capabilities().SupportsVersion(version) })
}

//nolint:cyclop,gocognit
func selectCipherSuites(selectedIDs []cryptosuite.ID, customCipherSuites func() []cryptosuite.Suite, includeCertificateSuites, includePSKSuites bool, minVersion, maxVersion protocol.Version) ([]cryptosuite.Suite, error) {
	customByID := make(map[cryptosuite.ID]cryptosuite.Suite)
	var custom []cryptosuite.Suite
	if customCipherSuites != nil {
		custom = customCipherSuites()
		for _, suite := range custom {
			if suite == nil || ciphersuite.ForID(suite.ID()) != nil || customByID[suite.ID()] != nil {
				return nil, dtlserrors.ErrInvalidCipherSuite
			}
			if err := validateCipherSuite(suite); err != nil {
				return nil, err
			}
			customByID[suite.ID()] = suite
		}
	}

	var cipherSuites []cryptosuite.Suite
	if selectedIDs != nil {
		cipherSuites = make([]cryptosuite.Suite, 0, len(selectedIDs))
		for _, id := range selectedIDs {
			suite := customByID[id]
			if suite == nil {
				suite = ciphersuite.ForID(id)
			}
			if suite == nil {
				return nil, &invalidCipherSuiteError{id}
			}
			if err := validateCipherSuite(suite); err != nil {
				return nil, err
			}
			cipherSuites = append(cipherSuites, suite)
		}
	} else {
		for _, version := range dtlsconfig.SupportedVersionsRange(minVersion, maxVersion) {
			cipherSuites = append(cipherSuites, defaultCipherSuitesForVersion(version)...)
		}
	}

	// Without an explicit ID list, external suites are enabled ahead of the
	// defaults. With an explicit list, the provider is only a registry.
	if selectedIDs == nil && len(custom) > 0 {
		cipherSuites = append(append(make([]cryptosuite.Suite, 0, len(custom)+len(cipherSuites)), custom...), cipherSuites...)
	}

	versions := dtlsconfig.SupportedVersionsRange(minVersion, maxVersion)
	cipherSuites = slices.DeleteFunc(cipherSuites, func(suite cryptosuite.Suite) bool {
		return !slices.ContainsFunc(versions, suite.Capabilities().SupportsVersion)
	})

	// Drop ciphers the Go FIPS module can't provide when FIPS mode is on,
	// mirroring effectiveEllipticCurves/filterFIPSCurves above.
	if fips140.Enabled() {
		cipherSuites = slices.DeleteFunc(cipherSuites, func(suite cryptosuite.Suite) bool {
			return !cipherSuiteFIPSApproved(suite.ID())
		})
	}

	var foundCertificateSuite, foundPSKSuite, foundTrafficSuite bool
	i := 0
	for _, suite := range cipherSuites {
		if suite.Capabilities().SupportsVersion(protocol.Version1_3) {
			foundTrafficSuite = true
			cipherSuites[i] = suite
			i++

			continue
		}
		switch {
		case includeCertificateSuites && suite.AuthenticationType() == cryptosuite.AuthenticationTypeCertificate:
			foundCertificateSuite = true
		case includePSKSuites && suite.AuthenticationType() == cryptosuite.AuthenticationTypePreSharedKey:
			foundPSKSuite = true
		case suite.AuthenticationType() == cryptosuite.AuthenticationTypeAnonymous:
		default:
			continue
		}
		cipherSuites[i] = suite
		i++
	}

	switch {
	case includeCertificateSuites && !foundCertificateSuite && !foundTrafficSuite:
		return nil, dtlserrors.ErrNoAvailableCertificateCipherSuite
	case includePSKSuites && !foundPSKSuite && !foundTrafficSuite:
		return nil, dtlserrors.ErrNoAvailablePSKCipherSuite
	case i == 0:
		return nil, dtlserrors.ErrNoAvailableCipherSuites
	}

	return cipherSuites[:i], nil
}

func validateCipherSuite(suite cryptosuite.Suite) error { //nolint:cyclop
	if suite == nil || suite.ID() == 0 {
		return dtlserrors.ErrInvalidCipherSuite
	}
	hashFunc := suite.HashFunc()
	if hashFunc == nil {
		return dtlserrors.ErrInvalidCipherSuite
	}
	hashInstance := hashFunc()
	if hashInstance == nil || hashInstance.Size() <= 0 || hashInstance.BlockSize() <= 0 {
		return dtlserrors.ErrInvalidCipherSuite
	}

	switch suite.Capabilities().Version() {
	case protocol.Version1_2:
		if _, ok := suite.(cryptosuite.ConnectionSuite); !ok {
			return dtlserrors.ErrInvalidCipherSuite
		}
	case protocol.Version1_3:
		if _, ok := suite.(cryptosuite.TrafficSuite); !ok {
			return dtlserrors.ErrInvalidCipherSuite
		}
	default:
		return dtlserrors.ErrInvalidCipherSuite
	}

	return nil
}

func filterCipherSuitesForCertificate(
	cert *tls.Certificate,
	cipherSuites []cryptosuite.Suite,
) []cryptosuite.Suite {
	if cert == nil || cert.PrivateKey == nil {
		return cipherSuites
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return cipherSuites
	}

	var certType clientcertificate.Type
	switch signer.Public().(type) {
	case ed25519.PublicKey, *ecdsa.PublicKey:
		certType = clientcertificate.ECDSASign
	case *rsa.PublicKey:
		certType = clientcertificate.RSASign
	}

	return slices.DeleteFunc(slices.Clone(cipherSuites), func(suite cryptosuite.Suite) bool {
		return !suite.Capabilities().SupportsVersion(protocol.Version1_3) && suite.AuthenticationType() == cryptosuite.AuthenticationTypeCertificate && certType != suite.CertificateType()
	})
}

// effectiveProtocolVersionRange restricts a configured version range to the
// versions supported by explicitly selected cipher suites and curves. This
// prevents advertising a version for which the local configuration cannot
// complete a handshake.
func effectiveProtocolVersionRange(config *dtlsConfig) (protocol.Version, protocol.Version, error) {
	minVersion, maxVersion := dtlsconfig.NormalizeProtocolVersionRange(config.MinVersion, config.MaxVersion)
	versions := dtlsconfig.SupportedVersionsRange(minVersion, maxVersion)

	if cipherVersions := supportedCipherSuiteVersions(config.CipherSuites, config.customCipherSuites, versions); len(cipherVersions) != 0 {
		versions = cipherVersions
	}

	curveVersions := supportedEllipticCurveVersions(config.EllipticCurves, dtlsconfig.SupportedVersionsRange(minVersion, maxVersion))
	if len(config.EllipticCurves) != 0 && len(curveVersions) == 0 {
		return 0, 0, dtlserrors.ErrUnsupportedEllipticCurveVersion
	}
	versions = intersectSupportedVersions(versions, curveVersions)

	if len(versions) == 0 {
		return 0, 0, dtlserrors.ErrNoCommonProtocolVersion
	}

	return versions[len(versions)-1], versions[0], nil
}

func supportedCipherSuiteVersions(suites []cryptosuite.ID, customCipherSuites func() []cryptosuite.Suite, versions []protocol.Version) []protocol.Version {
	if suites == nil {
		return versions
	}

	customByID := make(map[cryptosuite.ID]cryptosuite.Suite)
	if customCipherSuites != nil {
		for _, suite := range customCipherSuites() {
			if suite != nil {
				customByID[suite.ID()] = suite
			}
		}
	}
	descriptors := make([]cryptosuite.Suite, 0, len(suites))
	for _, id := range suites {
		suite := customByID[id]
		if suite == nil {
			suite = ciphersuite.ForID(id)
		}
		if suite == nil {
			return versions
		}
		descriptors = append(descriptors, suite)
	}

	return filterSupportedVersions(versions, func(version protocol.Version) bool {
		return slices.ContainsFunc(descriptors, func(suite cryptosuite.Suite) bool { return suite.Capabilities().SupportsVersion(version) })
	})
}

func supportedEllipticCurveVersions(
	curves []elliptic.Curve,
	versions []protocol.Version,
) []protocol.Version {
	if len(curves) == 0 {
		return versions
	}

	return filterSupportedVersions(versions, func(version protocol.Version) bool {
		return slices.ContainsFunc(curves, func(curve elliptic.Curve) bool {
			return curve != elliptic.X25519MLKEM768 || version == protocol.Version1_3
		})
	})
}

func filterSupportedVersions(
	versions []protocol.Version,
	supports func(protocol.Version) bool,
) []protocol.Version {
	filtered := make([]protocol.Version, 0, len(versions))
	for _, version := range versions {
		if supports(version) {
			filtered = append(filtered, version)
		}
	}

	return filtered
}

func intersectSupportedVersions(
	left, right []protocol.Version,
) []protocol.Version {
	return filterSupportedVersions(left, func(version protocol.Version) bool {
		return slices.Contains(right, version)
	})
}
