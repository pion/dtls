package dtls

import (
	"fmt"
	"hash"

	"github.com/pion/dtls/v2/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
)

// CipherSuiteID is an ID for our supported CipherSuites
type CipherSuiteID uint16

// Supported Cipher Suites
const (
	// AES-128-CCM
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM   CipherSuiteID = 0xc0ac //nolint:golint,stylecheck
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 CipherSuiteID = 0xc0ae //nolint:golint,stylecheck

	// AES-128-GCM-SHA256
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 CipherSuiteID = 0xc02b //nolint:golint,stylecheck
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   CipherSuiteID = 0xc02f //nolint:golint,stylecheck

	// AES-256-CBC-SHA
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA CipherSuiteID = 0xc00a //nolint:golint,stylecheck
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA   CipherSuiteID = 0xc014 //nolint:golint,stylecheck

	TLS_PSK_WITH_AES_128_CCM        CipherSuiteID = 0xc0a4 //nolint:golint,stylecheck
	TLS_PSK_WITH_AES_128_CCM_8      CipherSuiteID = 0xc0a8 //nolint:golint,stylecheck
	TLS_PSK_WITH_AES_128_GCM_SHA256 CipherSuiteID = 0x00a8 //nolint:golint,stylecheck
	TLS_PSK_WITH_AES_128_CBC_SHA256 CipherSuiteID = 0x00ae //nolint:golint,stylecheck
)

var _ = allCipherSuites() // Necessary until this function isn't only used by Go 1.14

func (c CipherSuiteID) String() string {
	switch c {
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"
	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case TLS_PSK_WITH_AES_128_CCM:
		return "TLS_PSK_WITH_AES_128_CCM"
	case TLS_PSK_WITH_AES_128_CCM_8:
		return "TLS_PSK_WITH_AES_128_CCM_8"
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		return "TLS_PSK_WITH_AES_128_GCM_SHA256"
	case TLS_PSK_WITH_AES_128_CBC_SHA256:
		return "TLS_PSK_WITH_AES_128_CBC_SHA256"
	default:
		return fmt.Sprintf("unknown(%v)", uint16(c))
	}
}

type cipherSuite interface {
	String() string
	ID() CipherSuiteID
	certificateType() clientcertificate.Type
	hashFunc() func() hash.Hash
	isPSK() bool
	isInitialized() bool

	// Generate the internal encryption state
	init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error

	encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error)
	decrypt(in []byte) ([]byte, error)
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
	switch id {
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
		return newCipherSuiteTLSEcdheEcdsaWithAes128Ccm()
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
		return newCipherSuiteTLSEcdheEcdsaWithAes128Ccm8()
	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return &cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{}
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return &cipherSuiteTLSEcdheRsaWithAes128GcmSha256{}
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return &cipherSuiteTLSEcdheEcdsaWithAes256CbcSha{}
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return &cipherSuiteTLSEcdheRsaWithAes256CbcSha{}
	case TLS_PSK_WITH_AES_128_CCM:
		return newCipherSuiteTLSPskWithAes128Ccm()
	case TLS_PSK_WITH_AES_128_CCM_8:
		return newCipherSuiteTLSPskWithAes128Ccm8()
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		return &cipherSuiteTLSPskWithAes128GcmSha256{}
	case TLS_PSK_WITH_AES_128_CBC_SHA256:
		return &cipherSuiteTLSPskWithAes128CbcSha256{}
	}
	return nil
}

// CipherSuites we support in order of preference
func defaultCipherSuites() []cipherSuite {
	return []cipherSuite{
		&cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{},
		&cipherSuiteTLSEcdheRsaWithAes128GcmSha256{},
		&cipherSuiteTLSEcdheEcdsaWithAes256CbcSha{},
		&cipherSuiteTLSEcdheRsaWithAes256CbcSha{},
	}
}

func allCipherSuites() []cipherSuite {
	return []cipherSuite{
		newCipherSuiteTLSEcdheEcdsaWithAes128Ccm(),
		newCipherSuiteTLSEcdheEcdsaWithAes128Ccm8(),
		&cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{},
		&cipherSuiteTLSEcdheRsaWithAes128GcmSha256{},
		&cipherSuiteTLSEcdheEcdsaWithAes256CbcSha{},
		&cipherSuiteTLSEcdheRsaWithAes256CbcSha{},
		newCipherSuiteTLSPskWithAes128Ccm(),
		newCipherSuiteTLSPskWithAes128Ccm8(),
		&cipherSuiteTLSPskWithAes128GcmSha256{},
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
		case includeCertificateSuites && !c.isPSK():
			foundCertificateSuite = true
		case includePSKSuites && c.isPSK():
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
