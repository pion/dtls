package dtls

import "encoding/binary"

type cipherSuiteID uint16

// Taken from https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
// A cipherSuite is a specific combination of key agreement, cipher and MAC
// function.
const (
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipherSuiteID = 0xc02b
)

type cipherSuite struct {
	id cipherSuiteID
}

var cipherSuites = map[cipherSuiteID]*cipherSuite{
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {id: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
}

var defaultCipherSuites = []*cipherSuite{
	cipherSuites[TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
}

func decodeCipherSuites(buf []byte) ([]*cipherSuite, error) {
	cipherSuitesCount := int(binary.BigEndian.Uint16(buf[0:])) / 2
	rtrn := []*cipherSuite{}
	for i := 0; i < cipherSuitesCount; i++ {
		id := cipherSuiteID(binary.BigEndian.Uint16(buf[(i*2)+2:]))
		if cipherSuite, ok := cipherSuites[id]; ok {
			rtrn = append(rtrn, cipherSuite)
		}
	}
	return rtrn, nil
}

func encodeCipherSuites(c []*cipherSuite) []byte {
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(c)*2))
	for i := len(c); i > 0; i-- {
		out = append(out, []byte{0x00, 0x00}...)
		binary.BigEndian.PutUint16(out[len(out)-2:], uint16(c[i-1].id))
	}

	return out
}
