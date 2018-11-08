package dtls

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type namedCurve uint16

type namedCurveKeypair struct {
	curve      namedCurve
	publicKey  []byte
	privateKey []byte
}

const (
	namedCurveP256   namedCurve = 0x0017
	namedCurveX25519            = 0x001d
)

var namedCurves = map[namedCurve]bool{
	namedCurveX25519: true,
	namedCurveP256:   true,
}

func generateKeypair(c namedCurve) (*namedCurveKeypair, error) {
	if c != namedCurveX25519 {
		return nil, errInvalidNamedCurve
	}

	tmp := make([]byte, 32)
	if _, err := rand.Read(tmp); err != nil {
		return nil, err
	}

	var public, private [32]byte
	copy(private[:], tmp)

	curve25519.ScalarBaseMult(&public, &private)
	return &namedCurveKeypair{namedCurveX25519, public[:], private[:]}, nil
}
