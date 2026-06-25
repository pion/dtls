// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"hash"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// CipherSuiteID is an ID for our supported CipherSuites.
type CipherSuiteID = ciphersuite.ID

// Supported Cipher Suites.
const (
	// TLS 1.3.
	TLS_AES_128_GCM_SHA256       CipherSuiteID = ciphersuite.TLS_AES_128_GCM_SHA256       // nolint: revive,staticcheck,lll
	TLS_AES_256_GCM_SHA384       CipherSuiteID = ciphersuite.TLS_AES_256_GCM_SHA384       // nolint: revive,staticcheck,lll
	TLS_CHACHA20_POLY1305_SHA256 CipherSuiteID = ciphersuite.TLS_CHACHA20_POLY1305_SHA256 // nolint: revive,staticcheck,lll

	// nolint: godot
	// AES-128-CCM
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM   CipherSuiteID = ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM   // nolint: revive,staticcheck,lll
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 CipherSuiteID = ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 // nolint: revive,staticcheck,lll

	// nolint: godot
	// AES-128-GCM-SHA256
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 CipherSuiteID = ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 // nolint: revive,staticcheck,lll
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   CipherSuiteID = ciphersuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   // nolint: revive,staticcheck,lll

	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 CipherSuiteID = ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 // nolint: revive,staticcheck,lll
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   CipherSuiteID = ciphersuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   // nolint: revive,staticcheck,lll

	// nolint: godot
	// AES-256-CBC-SHA
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA CipherSuiteID = ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA // nolint: revive,staticcheck,lll
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA   CipherSuiteID = ciphersuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA   // nolint: revive,staticcheck,lll

	TLS_PSK_WITH_AES_128_CCM        CipherSuiteID = ciphersuite.TLS_PSK_WITH_AES_128_CCM        // nolint: revive,staticcheck,lll
	TLS_PSK_WITH_AES_128_CCM_8      CipherSuiteID = ciphersuite.TLS_PSK_WITH_AES_128_CCM_8      // nolint: revive,staticcheck,lll
	TLS_PSK_WITH_AES_256_CCM_8      CipherSuiteID = ciphersuite.TLS_PSK_WITH_AES_256_CCM_8      // nolint: revive,staticcheck,lll
	TLS_PSK_WITH_AES_128_GCM_SHA256 CipherSuiteID = ciphersuite.TLS_PSK_WITH_AES_128_GCM_SHA256 // nolint: revive,staticcheck,lll
	TLS_PSK_WITH_AES_128_CBC_SHA256 CipherSuiteID = ciphersuite.TLS_PSK_WITH_AES_128_CBC_SHA256 // nolint: revive,staticcheck,lll

	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 CipherSuiteID = ciphersuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 // nolint: revive,staticcheck,lll

	// nolint: godot
	// ChaCha20-Poly1305-SHA256
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 CipherSuiteID = ciphersuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 // nolint: revive,staticcheck,lll
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   CipherSuiteID = ciphersuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   // nolint: revive,staticcheck,lll
	TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         CipherSuiteID = ciphersuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         // nolint: revive,staticcheck,lll
)

// CipherSuiteAuthenticationType controls what authentication method is using during the handshake for a CipherSuite.
type CipherSuiteAuthenticationType = ciphersuite.AuthenticationType

// AuthenticationType Enums.
const (
	CipherSuiteAuthenticationTypeCertificate  CipherSuiteAuthenticationType = ciphersuite.AuthenticationTypeCertificate
	CipherSuiteAuthenticationTypePreSharedKey CipherSuiteAuthenticationType = ciphersuite.AuthenticationTypePreSharedKey
	CipherSuiteAuthenticationTypeAnonymous    CipherSuiteAuthenticationType = ciphersuite.AuthenticationTypeAnonymous
)

// CipherSuiteKeyExchangeAlgorithm controls what exchange algorithm is using during the handshake for a CipherSuite.
type CipherSuiteKeyExchangeAlgorithm = ciphersuite.KeyExchangeAlgorithm

// CipherSuiteKeyExchangeAlgorithm Bitmask.
const (
	CipherSuiteKeyExchangeAlgorithmNone  CipherSuiteKeyExchangeAlgorithm = ciphersuite.KeyExchangeAlgorithmNone
	CipherSuiteKeyExchangeAlgorithmPsk   CipherSuiteKeyExchangeAlgorithm = ciphersuite.KeyExchangeAlgorithmPsk
	CipherSuiteKeyExchangeAlgorithmEcdhe CipherSuiteKeyExchangeAlgorithm = ciphersuite.KeyExchangeAlgorithmEcdhe
)

// CipherSuite is an interface that all DTLS CipherSuites must satisfy.
type CipherSuite interface {
	// String of CipherSuite, only used for logging
	String() string

	// ID of CipherSuite.
	ID() CipherSuiteID

	// What type of Certificate does this CipherSuite use
	CertificateType() clientcertificate.Type

	// What Hash function is used during verification
	HashFunc() func() hash.Hash

	// AuthenticationType controls what authentication method is using during the handshake
	AuthenticationType() CipherSuiteAuthenticationType

	// KeyExchangeAlgorithm controls what exchange algorithm is using during the handshake
	KeyExchangeAlgorithm() CipherSuiteKeyExchangeAlgorithm

	// ECC (Elliptic Curve Cryptography) determines whether ECC extesions will be send during handshake.
	// https://datatracker.ietf.org/doc/html/rfc4492#page-10
	ECC() bool

	// Called when keying material has been generated, should initialize the internal cipher
	Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error
	IsInitialized() bool
	Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error)
	Decrypt(h recordlayer.Header, in []byte) ([]byte, error)
}

// VersionDTLS12 is the DTLS version in the same style as VersionTLSXX from crypto/tls.
const VersionDTLS12 = 0xfefd

// VersionDTLS13 is the DTLS version in the same style as VersionTLSXX from crypto/tls.
const VersionDTLS13 = 0xfefc

// CipherSuiteName provides the same functionality as tls.CipherSuiteName
// that appeared first in Go 1.14.
//
// Our implementation differs slightly in that it takes in a CipherSuiteID,
// like the rest of our library, instead of a uint16 like crypto/tls.
func CipherSuiteName(id CipherSuiteID) string {
	suite := cipherSuiteForID(id)
	if suite != nil {
		return suite.String()
	}

	return fmt.Sprintf("0x%04X", uint16(id))
}

// Convert from our cipherSuite interface to a tls.CipherSuite struct.
func toTLSCipherSuite(c CipherSuite) *tls.CipherSuite {
	return &tls.CipherSuite{
		ID:                uint16(c.ID()),
		Name:              c.String(),
		SupportedVersions: cipherSuiteSupportedVersionIDs(c.ID()),
		Insecure:          false,
	}
}

// CipherSuites returns a list of cipher suites currently known by this
// package, excluding those with security issues, which are returned by
// InsecureCipherSuites.
func CipherSuites() []*tls.CipherSuite {
	suites := allCipherSuites()
	res := make([]*tls.CipherSuite, len(suites))
	for i, c := range suites {
		res[i] = toTLSCipherSuite(c)
	}

	return res
}

// InsecureCipherSuites returns a list of cipher suites currently implemented by
// this package and which have security issues.
func InsecureCipherSuites() []*tls.CipherSuite {
	var res []*tls.CipherSuite

	return res
}

// Taken from https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
// A cipherSuite is a specific combination of key agreement, cipher and MAC
// function.
func cipherSuiteForID(id CipherSuiteID) CipherSuite {
	return ciphersuite.ForID(id, nil)
}

// TLS 1.3 CipherSuites we support in order of preference.
func defaultCipherSuites13() []CipherSuite {
	return []CipherSuite{
		ciphersuite.NewTLSAes128GcmSha256(),
		ciphersuite.NewTLSAes256GcmSha384(),
		ciphersuite.NewTLSChacha20Poly1305Sha256(),
	}
}

// CipherSuites we support in order of preference.
func defaultCipherSuites() []CipherSuite {
	return []CipherSuite{
		&ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{},
		&ciphersuite.TLSEcdheRsaWithAes128GcmSha256{},
		&ciphersuite.TLSEcdheEcdsaWithChacha20Poly1305Sha256{},
		&ciphersuite.TLSEcdheRsaWithChacha20Poly1305Sha256{},
		&ciphersuite.TLSEcdheEcdsaWithAes256CbcSha{},
		&ciphersuite.TLSEcdheRsaWithAes256CbcSha{},
		&ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{},
		&ciphersuite.TLSEcdheRsaWithAes256GcmSha384{},
	}
}

func allCipherSuites() []CipherSuite {
	return []CipherSuite{
		ciphersuite.NewTLSAes128GcmSha256(),
		ciphersuite.NewTLSAes256GcmSha384(),
		ciphersuite.NewTLSChacha20Poly1305Sha256(),
		ciphersuite.NewTLSEcdheEcdsaWithAes128Ccm(),
		ciphersuite.NewTLSEcdheEcdsaWithAes128Ccm8(),
		&ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{},
		&ciphersuite.TLSEcdheRsaWithAes128GcmSha256{},
		&ciphersuite.TLSEcdheEcdsaWithAes256CbcSha{},
		&ciphersuite.TLSEcdheRsaWithAes256CbcSha{},
		ciphersuite.NewTLSPskWithAes128Ccm(),
		ciphersuite.NewTLSPskWithAes128Ccm8(),
		ciphersuite.NewTLSPskWithAes256Ccm8(),
		&ciphersuite.TLSPskWithAes128GcmSha256{},
		&ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{},
		&ciphersuite.TLSEcdheRsaWithAes256GcmSha384{},
		&ciphersuite.TLSEcdheEcdsaWithChacha20Poly1305Sha256{},
		&ciphersuite.TLSEcdheRsaWithChacha20Poly1305Sha256{},
		&ciphersuite.TLSPskWithChacha20Poly1305Sha256{},
	}
}

func cipherSuiteIDs(cipherSuites []CipherSuite) []uint16 {
	rtrn := []uint16{}
	for _, c := range cipherSuites {
		rtrn = append(rtrn, uint16(c.ID()))
	}

	return rtrn
}

func configCipherSuiteIDs(cipherSuites []ciphersuite.CipherSuite) []uint16 {
	rtrn := []uint16{}
	for _, c := range cipherSuites {
		rtrn = append(rtrn, uint16(c.ID()))
	}

	return rtrn
}

func defaultCipherSuitesForVersions(minVersion, maxVersion protocol.Version) []CipherSuite {
	cipherSuites := []CipherSuite{}
	for _, version := range supportedVersionsRange(minVersion, maxVersion) {
		switch {
		case version.Equal(protocol.Version1_3):
			cipherSuites = append(cipherSuites, defaultCipherSuites13()...)
		case version.Equal(protocol.Version1_2):
			cipherSuites = append(cipherSuites, defaultCipherSuites()...)
		}
	}

	return cipherSuites
}

func cipherSuiteSupportedVersions(id CipherSuiteID) []protocol.Version {
	return ciphersuite.SupportedVersions(id)
}

func cipherSuiteSupportedVersionIDs(id CipherSuiteID) []uint16 {
	return ciphersuite.SupportedVersionIDs(id)
}

func cipherSuiteIDSupportsVersion(id CipherSuiteID, version protocol.Version) bool {
	return ciphersuite.IDSupportsVersion(id, version)
}

func cipherSuiteIDSupportsVersions(id CipherSuiteID, minVersion, maxVersion protocol.Version) bool {
	for _, version := range supportedVersionsRange(minVersion, maxVersion) {
		if cipherSuiteIDSupportsVersion(id, version) {
			return true
		}
	}

	return false
}

func filterCipherSuitesForVersion(
	cipherSuites []ciphersuite.CipherSuite,
	version protocol.Version,
) []ciphersuite.CipherSuite {
	filtered := make([]ciphersuite.CipherSuite, 0, len(cipherSuites))
	for _, c := range cipherSuites {
		if cipherSuiteIDSupportsVersion(c.ID(), version) {
			filtered = append(filtered, c)
		}
	}

	return filtered
}

func filterCipherSuitesForVersions(
	cipherSuites []ciphersuite.CipherSuite,
	minVersion, maxVersion protocol.Version,
) []ciphersuite.CipherSuite {
	filtered := make([]ciphersuite.CipherSuite, 0, len(cipherSuites))
	for _, c := range cipherSuites {
		if cipherSuiteIDSupportsVersions(c.ID(), minVersion, maxVersion) {
			filtered = append(filtered, c)
		}
	}

	return filtered
}

//nolint:cyclop
func parseCipherSuites(
	userSelectedSuites []CipherSuiteID,
	customCipherSuites func() []CipherSuite,
	includeCertificateSuites, includePSKSuites bool,
) ([]ciphersuite.CipherSuite, error) {
	return parseCipherSuitesForVersions(
		userSelectedSuites,
		customCipherSuites,
		includeCertificateSuites,
		includePSKSuites,
		protocol.Version1_2,
		protocol.Version1_2,
	)
}

//nolint:cyclop
func parseCipherSuitesForVersions(
	userSelectedSuites []CipherSuiteID,
	customCipherSuites func() []CipherSuite,
	includeCertificateSuites, includePSKSuites bool,
	minVersion, maxVersion protocol.Version,
) ([]ciphersuite.CipherSuite, error) {
	cipherSuitesForIDs := func(ids []CipherSuiteID) ([]ciphersuite.CipherSuite, error) {
		cipherSuites := []ciphersuite.CipherSuite{}
		for _, id := range ids {
			c := cipherSuiteForID(id)
			if c == nil {
				return nil, &invalidCipherSuiteError{id}
			}
			cipherSuites = append(cipherSuites, c)
		}

		return cipherSuites, nil
	}

	var (
		cipherSuites []ciphersuite.CipherSuite
		err          error
		i            int
	)
	if userSelectedSuites != nil {
		cipherSuites, err = cipherSuitesForIDs(userSelectedSuites)
		if err != nil {
			return nil, err
		}
	} else {
		cipherSuites = toConfigCipherSuites(defaultCipherSuitesForVersions(minVersion, maxVersion))
	}

	// Put CustomCipherSuites before ID selected suites
	if customCipherSuites != nil {
		custom := customCipherSuites()
		configCipherSuites := make([]ciphersuite.CipherSuite, 0, len(custom)+len(cipherSuites))
		for _, cipherSuite := range custom {
			configCipherSuites = append(configCipherSuites, cipherSuite)
		}
		cipherSuites = append(configCipherSuites, cipherSuites...)
	}

	cipherSuites = filterCipherSuitesForVersions(cipherSuites, minVersion, maxVersion)

	var foundCertificateSuite, foundPSKSuite, foundAnonymousSuite, foundTLS13Suite bool
	for _, cipher := range cipherSuites {
		switch {
		case includeCertificateSuites && cipher.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate:
			foundCertificateSuite = true
		case includePSKSuites && cipher.AuthenticationType() == CipherSuiteAuthenticationTypePreSharedKey:
			foundPSKSuite = true
		case cipher.AuthenticationType() == CipherSuiteAuthenticationTypeAnonymous:
			foundAnonymousSuite = true
			if cipherSuiteIDSupportsVersion(cipher.ID(), protocol.Version1_3) {
				foundTLS13Suite = true
			}
		default:
			continue
		}
		cipherSuites[i] = cipher
		i++
	}

	switch {
	case includeCertificateSuites && !foundCertificateSuite && !foundAnonymousSuite:
		return nil, dtlserrors.ErrNoAvailableCertificateCipherSuite
	case includePSKSuites && !foundPSKSuite && !foundTLS13Suite:
		return nil, dtlserrors.ErrNoAvailablePSKCipherSuite
	case i == 0:
		return nil, dtlserrors.ErrNoAvailableCipherSuites
	}

	return cipherSuites[:i], nil
}

func filterCipherSuitesForCertificate(
	cert *tls.Certificate,
	cipherSuites []ciphersuite.CipherSuite,
) []ciphersuite.CipherSuite {
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

	filtered := []ciphersuite.CipherSuite{}
	for _, c := range cipherSuites {
		if c.AuthenticationType() != CipherSuiteAuthenticationTypeCertificate || certType == c.CertificateType() {
			filtered = append(filtered, c)
		}
	}

	return filtered
}
