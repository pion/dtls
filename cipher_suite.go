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
	"slices"

	"github.com/pion/dtls/v3/internal/ciphersuite"
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
	suite := cipherSuiteForID(id, nil)
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
func cipherSuiteForID(id CipherSuiteID, customCiphers func() []CipherSuite) CipherSuite { //nolint:cyclop
	switch id { //nolint:exhaustive
	case TLS_AES_128_GCM_SHA256:
		return ciphersuite.NewTLSAes128GcmSha256()
	case TLS_AES_256_GCM_SHA384:
		return ciphersuite.NewTLSAes256GcmSha384()
	case TLS_CHACHA20_POLY1305_SHA256:
		return ciphersuite.NewTLSChacha20Poly1305Sha256()
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
		return ciphersuite.NewTLSEcdheEcdsaWithAes128Ccm()
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
		return ciphersuite.NewTLSEcdheEcdsaWithAes128Ccm8()
	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return &ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return &ciphersuite.TLSEcdheRsaWithAes128GcmSha256{}
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return &ciphersuite.TLSEcdheEcdsaWithAes256CbcSha{}
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return &ciphersuite.TLSEcdheRsaWithAes256CbcSha{}
	case TLS_PSK_WITH_AES_128_CCM:
		return ciphersuite.NewTLSPskWithAes128Ccm()
	case TLS_PSK_WITH_AES_128_CCM_8:
		return ciphersuite.NewTLSPskWithAes128Ccm8()
	case TLS_PSK_WITH_AES_256_CCM_8:
		return ciphersuite.NewTLSPskWithAes256Ccm8()
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		return &ciphersuite.TLSPskWithAes128GcmSha256{}
	case TLS_PSK_WITH_AES_128_CBC_SHA256:
		return &ciphersuite.TLSPskWithAes128CbcSha256{}
	case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return &ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{}
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return &ciphersuite.TLSEcdheRsaWithAes256GcmSha384{}
	case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
		return ciphersuite.NewTLSEcdhePskWithAes128CbcSha256()
	case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return &ciphersuite.TLSEcdheEcdsaWithChacha20Poly1305Sha256{}
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return &ciphersuite.TLSEcdheRsaWithChacha20Poly1305Sha256{}
	case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return &ciphersuite.TLSPskWithChacha20Poly1305Sha256{}
	}

	if customCiphers != nil {
		for _, c := range customCiphers() {
			if c.ID() == id {
				return c
			}
		}
	}

	return nil
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

func knownCipherSuiteSupportedVersions(id CipherSuiteID) ([]protocol.Version, bool) {
	switch id { //nolint:exhaustive
	case TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256:
		return []protocol.Version{protocol.Version1_3}, true
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_PSK_WITH_AES_128_CCM,
		TLS_PSK_WITH_AES_128_CCM_8,
		TLS_PSK_WITH_AES_256_CCM_8,
		TLS_PSK_WITH_AES_128_GCM_SHA256,
		TLS_PSK_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return []protocol.Version{protocol.Version1_2}, true
	default:
		return nil, false
	}
}

func cipherSuiteSupportedVersions(id CipherSuiteID) []protocol.Version {
	if versions, ok := knownCipherSuiteSupportedVersions(id); ok {
		return versions
	}

	return []protocol.Version{protocol.Version1_2}
}

func cipherSuiteSupportedVersionIDs(id CipherSuiteID) []uint16 {
	versions := cipherSuiteSupportedVersions(id)
	ids := make([]uint16, 0, len(versions))
	for _, version := range versions {
		ids = append(ids, protocolVersionID(version))
	}

	return ids
}

func protocolVersionID(version protocol.Version) uint16 {
	return uint16(version.Major)<<8 | uint16(version.Minor)
}

func cipherSuiteIDSupportsVersion(id CipherSuiteID, version protocol.Version) bool {
	return slices.ContainsFunc(cipherSuiteSupportedVersions(id), version.Equal)
}

func cipherSuiteIDSupportsVersions(id CipherSuiteID, minVersion, maxVersion protocol.Version) bool {
	for _, version := range supportedVersionsRange(minVersion, maxVersion) {
		if cipherSuiteIDSupportsVersion(id, version) {
			return true
		}
	}

	return false
}

func filterCipherSuitesForVersion(cipherSuites []CipherSuite, version protocol.Version) []CipherSuite {
	filtered := make([]CipherSuite, 0, len(cipherSuites))
	for _, c := range cipherSuites {
		if cipherSuiteIDSupportsVersion(c.ID(), version) {
			filtered = append(filtered, c)
		}
	}

	return filtered
}

func filterCipherSuitesForVersions(
	cipherSuites []CipherSuite,
	minVersion, maxVersion protocol.Version,
) []CipherSuite {
	filtered := make([]CipherSuite, 0, len(cipherSuites))
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
) ([]CipherSuite, error) {
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
) ([]CipherSuite, error) {
	cipherSuitesForIDs := func(ids []CipherSuiteID) ([]CipherSuite, error) {
		cipherSuites := []CipherSuite{}
		for _, id := range ids {
			c := cipherSuiteForID(id, nil)
			if c == nil {
				return nil, &invalidCipherSuiteError{id}
			}
			cipherSuites = append(cipherSuites, c)
		}

		return cipherSuites, nil
	}

	var (
		cipherSuites []CipherSuite
		err          error
		i            int
	)
	if userSelectedSuites != nil {
		cipherSuites, err = cipherSuitesForIDs(userSelectedSuites)
		if err != nil {
			return nil, err
		}
	} else {
		cipherSuites = defaultCipherSuitesForVersions(minVersion, maxVersion)
	}

	// Put CustomCipherSuites before ID selected suites
	if customCipherSuites != nil {
		cipherSuites = append(customCipherSuites(), cipherSuites...)
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
		return nil, errNoAvailableCertificateCipherSuite
	case includePSKSuites && !foundPSKSuite && !foundTLS13Suite:
		return nil, errNoAvailablePSKCipherSuite
	case i == 0:
		return nil, errNoAvailableCipherSuites
	}

	return cipherSuites[:i], nil
}

func filterCipherSuitesForCertificate(cert *tls.Certificate, cipherSuites []CipherSuite) []CipherSuite {
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

	filtered := []CipherSuite{}
	for _, c := range cipherSuites {
		if c.AuthenticationType() != CipherSuiteAuthenticationTypeCertificate || certType == c.CertificateType() {
			filtered = append(filtered, c)
		}
	}

	return filtered
}
