package dtls

import (
	"fmt"
	"hash"

	"github.com/pion/dtls/v2/internal/ciphersuite"
	"github.com/pion/dtls/v2/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
)

// CipherSuiteID is an ID for our supported CipherSuites
type CipherSuiteID = ciphersuite.ID

// Supported Cipher Suites
const (
	// AES-128-CCM
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM   CipherSuiteID = ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM   //nolint:golint,stylecheck
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 CipherSuiteID = ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 //nolint:golint,stylecheck

	// AES-128-GCM-SHA256
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 CipherSuiteID = ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 //nolint:golint,stylecheck
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   CipherSuiteID = ciphersuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   //nolint:golint,stylecheck

	// AES-256-CBC-SHA
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA CipherSuiteID = ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA //nolint:golint,stylecheck
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA   CipherSuiteID = ciphersuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA   //nolint:golint,stylecheck

	TLS_PSK_WITH_AES_128_CCM        CipherSuiteID = ciphersuite.TLS_PSK_WITH_AES_128_CCM        //nolint:golint,stylecheck
	TLS_PSK_WITH_AES_128_CCM_8      CipherSuiteID = ciphersuite.TLS_PSK_WITH_AES_128_CCM_8      //nolint:golint,stylecheck
	TLS_PSK_WITH_AES_128_GCM_SHA256 CipherSuiteID = ciphersuite.TLS_PSK_WITH_AES_128_GCM_SHA256 //nolint:golint,stylecheck
	TLS_PSK_WITH_AES_128_CBC_SHA256 CipherSuiteID = ciphersuite.TLS_PSK_WITH_AES_128_CBC_SHA256 //nolint:golint,stylecheck
)

var _ = allCipherSuites() // Necessary until this function isn't only used by Go 1.14

type cipherSuite interface {
	String() string
	ID() CipherSuiteID
	CertificateType() clientcertificate.Type
	HashFunc() func() hash.Hash
	IsPSK() bool
	IsInitialized() bool

	// Generate the internal encryption state
	Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error

	Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error)
	Decrypt(in []byte) ([]byte, error)
}

// CipherSuiteName provides the same functionality as tls.CipherSuiteName
// that appeared first in Go 1.14.
//
// Our implementation differs slightly in that it takes in a CiperSuiteID,
// like the rest of our library, instead of a uint16 like crypto/tls.
func CipherSuiteName(id CipherSuiteID) string {
	suite := cipherSuiteForID(id)
	if suite != nil {
		return suite.String()
	}
	return fmt.Sprintf("0x%04X", uint16(id))
}

// Taken from https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
// A cipherSuite is a specific combination of key agreement, cipher and MAC
// function.
func cipherSuiteForID(id CipherSuiteID) cipherSuite {
	switch id { //nolint:exhaustive
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
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		return &ciphersuite.TLSPskWithAes128GcmSha256{}
	case TLS_PSK_WITH_AES_128_CBC_SHA256:
		return &ciphersuite.TLSPskWithAes128CbcSha256{}
	}
	return nil
}

// CipherSuites we support in order of preference
func defaultCipherSuites() []cipherSuite {
	return []cipherSuite{
		&ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{},
		&ciphersuite.TLSEcdheRsaWithAes128GcmSha256{},
		&ciphersuite.TLSEcdheEcdsaWithAes256CbcSha{},
		&ciphersuite.TLSEcdheRsaWithAes256CbcSha{},
	}
}

func allCipherSuites() []cipherSuite {
	return []cipherSuite{
		ciphersuite.NewTLSEcdheEcdsaWithAes128Ccm(),
		ciphersuite.NewTLSEcdheEcdsaWithAes128Ccm8(),
		&ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{},
		&ciphersuite.TLSEcdheRsaWithAes128GcmSha256{},
		&ciphersuite.TLSEcdheEcdsaWithAes256CbcSha{},
		&ciphersuite.TLSEcdheRsaWithAes256CbcSha{},
		ciphersuite.NewTLSPskWithAes128Ccm(),
		ciphersuite.NewTLSPskWithAes128Ccm8(),
		&ciphersuite.TLSPskWithAes128GcmSha256{},
	}
}

func cipherSuiteIDs(cipherSuites []cipherSuite) []uint16 {
	rtrn := []uint16{}
	for _, c := range cipherSuites {
		rtrn = append(rtrn, uint16(c.ID()))
	}
	return rtrn
}

func parseCipherSuites(userSelectedSuites []CipherSuiteID, includeCertificateSuites, includePSKSuites bool) ([]cipherSuite, error) {
	if !includeCertificateSuites && !includePSKSuites {
		return nil, errNoAvailableCipherSuites
	}

	cipherSuitesForIDs := func(ids []CipherSuiteID) ([]cipherSuite, error) {
		cipherSuites := []cipherSuite{}
		for _, id := range ids {
			c := cipherSuiteForID(id)
			if c == nil {
				return nil, &invalidCipherSuite{id}
			}
			cipherSuites = append(cipherSuites, c)
		}
		return cipherSuites, nil
	}

	var (
		cipherSuites []cipherSuite
		err          error
		i            int
	)
	if len(userSelectedSuites) != 0 {
		cipherSuites, err = cipherSuitesForIDs(userSelectedSuites)
		if err != nil {
			return nil, err
		}
	} else {
		cipherSuites = defaultCipherSuites()
	}

	var foundCertificateSuite, foundPSKSuite bool
	for _, c := range cipherSuites {
		switch {
		case includeCertificateSuites && !c.IsPSK():
			foundCertificateSuite = true
		case includePSKSuites && c.IsPSK():
			foundPSKSuite = true
		default:
			continue
		}
		cipherSuites[i] = c
		i++
	}

	if includeCertificateSuites && !foundCertificateSuite {
		return nil, errNoAvailableCertificateCipherSuite
	}
	if includePSKSuites && !foundPSKSuite {
		return nil, errNoAvailablePSKCipherSuite
	}

	return cipherSuites[:i], nil
}
