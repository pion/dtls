package dtls

import (
	"encoding/binary"
	"fmt"
	"hash"
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

	// https://tools.ietf.org/html/rfc8422#section-6
	TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256 CipherSuiteID = 0xc018 //nolint:golint,stylecheck
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
	case TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256"
	default:
		return fmt.Sprintf("unknown(%v)", uint16(c))
	}
}

type CipherSuite interface {
	String() string
	ID() CipherSuiteID
	CertificateType() ClientCertificateType
	HashFunc() func() hash.Hash
	IsPSK() bool
	IsAnon() bool
	IsInitialized() bool

	// Generate the internal encryption state
	Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error

	Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error)
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
// A CipherSuite is a specific combination of key agreement, cipher and MAC
// function.
func cipherSuiteForID(id CipherSuiteID) CipherSuite {
	switch id {
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
		return NewCipherSuiteTLSEcdheEcdsaWithAes128Ccm()
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
		return NewCipherSuiteTLSEcdheEcdsaWithAes128Ccm8()
	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return &CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{}
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return &CipherSuiteTLSEcdheRsaWithAes128GcmSha256{}
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return &CipherSuiteTLSEcdheEcdsaWithAes256CbcSha{}
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return &CipherSuiteTLSEcdheRsaWithAes256CbcSha{}
	case TLS_PSK_WITH_AES_128_CCM:
		return NewCipherSuiteTLSPskWithAes128Ccm()
	case TLS_PSK_WITH_AES_128_CCM_8:
		return NewCipherSuiteTLSPskWithAes128Ccm8()
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		return &CipherSuiteTLSPskWithAes128GcmSha256{}
	case TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256:
		return NewCipherSuiteTLSEcdhAnonWithAes128CbcSha256(TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256)
	}
	return nil
}

// CipherSuites we support in order of preference
func defaultCipherSuites() []CipherSuite {
	return []CipherSuite{
		&CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{},
		&CipherSuiteTLSEcdheRsaWithAes128GcmSha256{},
		&CipherSuiteTLSEcdheEcdsaWithAes256CbcSha{},
		&CipherSuiteTLSEcdheRsaWithAes256CbcSha{},
	}
}

func allCipherSuites() []CipherSuite {
	return []CipherSuite{
		NewCipherSuiteTLSEcdheEcdsaWithAes128Ccm(),
		NewCipherSuiteTLSEcdheEcdsaWithAes128Ccm8(),
		&CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{},
		&CipherSuiteTLSEcdheRsaWithAes128GcmSha256{},
		&CipherSuiteTLSEcdheEcdsaWithAes256CbcSha{},
		&CipherSuiteTLSEcdheRsaWithAes256CbcSha{},
		NewCipherSuiteTLSPskWithAes128Ccm(),
		NewCipherSuiteTLSPskWithAes128Ccm8(),
		&CipherSuiteTLSPskWithAes128GcmSha256{},
	}
}

func decodeCipherSuitesIDs(buf []byte) ([]CipherSuiteID, error) {
	if len(buf) < 2 {
		return nil, errDTLSPacketInvalidLength
	}
	cipherSuitesCount := int(binary.BigEndian.Uint16(buf[0:])) / 2
	rtrn := make([]CipherSuiteID, 0, 8)
	for i := 0; i < cipherSuitesCount; i++ {
		if len(buf) < (i*2 + 4) {
			return nil, errBufferTooSmall
		}
		id := CipherSuiteID(binary.BigEndian.Uint16(buf[(i*2)+2:]))
		rtrn = append(rtrn, id)
	}
	return rtrn, nil
}

func decodeCipherSuites(buf []byte) ([]CipherSuite, error) {
	if len(buf) < 2 {
		return nil, errDTLSPacketInvalidLength
	}
	cipherSuitesCount := int(binary.BigEndian.Uint16(buf[0:])) / 2
	rtrn := []CipherSuite{}
	for i := 0; i < cipherSuitesCount; i++ {
		if len(buf) < (i*2 + 4) {
			return nil, errBufferTooSmall
		}
		id := CipherSuiteID(binary.BigEndian.Uint16(buf[(i*2)+2:]))
		if c := cipherSuiteForID(id); c != nil {
			rtrn = append(rtrn, c)
		}
	}
	return rtrn, nil
}

func encodeCipherSuitesIDs(cipherSuites []CipherSuiteID) []byte {
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(cipherSuites)*2))
	for _, c := range cipherSuites {
		out = append(out, []byte{0x00, 0x00}...)
		binary.BigEndian.PutUint16(out[len(out)-2:], uint16(c))
	}
	return out
}

func encodeCipherSuites(cipherSuites []CipherSuite) []byte {
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(cipherSuites)*2))
	for _, c := range cipherSuites {
		out = append(out, []byte{0x00, 0x00}...)
		binary.BigEndian.PutUint16(out[len(out)-2:], uint16(c.ID()))
	}
	return out
}

func appendCustomCipherSuites(orig []CipherSuite, customSuites []CipherSuite, excludePSK, excludeNonPSK bool) ([]CipherSuite, error) {
	for _, c := range customSuites {
		if excludePSK && c.IsPSK() || excludeNonPSK && !c.IsPSK() {
			continue
		}
		wantAppend := true
		for _, co := range orig {
			if c.ID() == co.ID() {
				wantAppend = false
				break
			}
		}
		if wantAppend {
			orig = append(orig, c)
		}
	}

	if len(orig) == 0 {
		return nil, errNoAvailableCipherSuites
	}
	return orig, nil
}

func parseCipherSuites(userSelectedSuites []CipherSuiteID, excludePSK, excludeNonPSK bool) ([]CipherSuite, error) {
	cipherSuitesForIDs := func(ids []CipherSuiteID) ([]CipherSuite, error) {
		cipherSuites := []CipherSuite{}
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
		cipherSuites []CipherSuite
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

	for _, c := range cipherSuites {
		if excludePSK && c.IsPSK() || excludeNonPSK && !c.IsPSK() {
			continue
		}
		cipherSuites[i] = c
		i++
	}

	cipherSuites = cipherSuites[:i]
	if len(cipherSuites) == 0 {
		return nil, errNoAvailableCipherSuites
	}

	return cipherSuites, nil
}
