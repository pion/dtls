package dtls

import (
	"encoding/binary"
	"hash"
)

type cipherSuiteID uint16

type cipherSuite interface {
	ID() cipherSuiteID
	certificateType() clientCertificateType
	hashFunc() func() hash.Hash

	// Generate the internal encryption state
	init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error

	encrypt(pkt *recordLayer, raw []byte) ([]byte, error)
	decrypt(in []byte) ([]byte, error)
}

// Taken from https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
// A cipherSuite is a specific combination of key agreement, cipher and MAC
// function.
func cipherSuiteForID(id cipherSuiteID) cipherSuite {
	switch id {
	case cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{}.ID():
		return &cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{}
	case cipherSuiteTLSEcdheRsaWithAes128GcmSha256{}.ID():
		return &cipherSuiteTLSEcdheRsaWithAes128GcmSha256{}
	case cipherSuiteTLSEcdheEcdsaWithAes256CbcSha{}.ID():
		return &cipherSuiteTLSEcdheEcdsaWithAes256CbcSha{}
	case cipherSuiteTLSEcdheRsaWithAes256CbcSha{}.ID():
		return &cipherSuiteTLSEcdheRsaWithAes256CbcSha{}
	}

	return nil
}

// CipherSuites we support as a client
// Preferred at the bottom
func clientCipherSuites() []cipherSuite {
	return []cipherSuite{
		&cipherSuiteTLSEcdheRsaWithAes256CbcSha{},
		&cipherSuiteTLSEcdheEcdsaWithAes256CbcSha{},
		&cipherSuiteTLSEcdheRsaWithAes128GcmSha256{},
		&cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{},
	}
}

// CipherSuites we support as a server
// func serverCipherSuites() []cipherSuite {
// 	return []cipherSuite{
// 		&cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{},
// 	}
// }

func decodeCipherSuites(buf []byte) ([]cipherSuite, error) {
	if len(buf) < 2 {
		return nil, errDTLSPacketInvalidLength
	}
	cipherSuitesCount := int(binary.BigEndian.Uint16(buf[0:])) / 2
	rtrn := []cipherSuite{}
	for i := 0; i < cipherSuitesCount; i++ {
		id := cipherSuiteID(binary.BigEndian.Uint16(buf[(i*2)+2:]))
		if c := cipherSuiteForID(id); c != nil {
			rtrn = append(rtrn, c)
		}
	}
	return rtrn, nil
}

func encodeCipherSuites(c []cipherSuite) []byte {
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(c)*2))
	for i := len(c); i > 0; i-- {
		out = append(out, []byte{0x00, 0x00}...)
		binary.BigEndian.PutUint16(out[len(out)-2:], uint16(c[i-1].ID()))
	}

	return out
}
