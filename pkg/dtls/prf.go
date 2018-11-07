package dtls

import (
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
)

const (
	prfMasterSecretLabel = "master secret"
)

type encryptionKeys struct {
	clientMACKey   []byte
	serverMACKey   []byte
	clientWriteKey []byte
	serverWriteKey []byte
	clientWriteIV  []byte
	serverWriteIV  []byte
}

func prfPreMasterSecret(publicKey, privateKey [32]byte, curve namedCurve) ([]byte, error) {
	if curve != namedCurveX25519 {
		return nil, errInvalidNamedCurve
	}

	var preMasterSecret [32]byte
	curve25519.ScalarMult(&preMasterSecret, &privateKey, &publicKey)
	return preMasterSecret[:], nil
}

func prfMasterSecret(preMasterSecret, clientRandom, serverRandom []byte) []byte {
	hmacSHA256 := func(key, data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil)
	}

	seed := append(append([]byte(prfMasterSecretLabel), clientRandom...), serverRandom...)
	a0 := seed
	a1 := hmacSHA256(preMasterSecret, a0)
	a2 := hmacSHA256(preMasterSecret, a1)
	p1 := hmacSHA256(preMasterSecret, append(a1, seed...))
	p2 := hmacSHA256(preMasterSecret, append(a2, seed...))

	return append(p1, p2[:16]...)
}

func prfEncryptionKeys() (e encryptionKeys) {
	return e
}
