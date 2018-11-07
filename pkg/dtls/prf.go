package dtls

import (
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
)

const (
	prfMasterSecretLabel = "master secret"
	prfKeyExpansionLabel = "key expansion"
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

func prfEncryptionKeys(masterSecret, clientRandom, serverRandom []byte) *encryptionKeys {
	hmacSHA256 := func(key, data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil)
	}

	seed := append(append([]byte(prfKeyExpansionLabel), serverRandom...), clientRandom...)
	a0 := seed
	a1 := hmacSHA256(masterSecret, a0)
	a2 := hmacSHA256(masterSecret, a1)
	a3 := hmacSHA256(masterSecret, a2)
	a4 := hmacSHA256(masterSecret, a3)

	p1 := hmacSHA256(masterSecret, append(a1, seed...))
	p2 := hmacSHA256(masterSecret, append(a2, seed...))
	p3 := hmacSHA256(masterSecret, append(a3, seed...))
	p4 := hmacSHA256(masterSecret, append(a4, seed...))
	p := append(append(append(p1, p2...), p3...), p4...)
	return &encryptionKeys{
		clientMACKey:   p[:20],
		serverMACKey:   p[20:40],
		clientWriteKey: p[40:56],
		serverWriteKey: p[56:72],
		clientWriteIV:  p[72:88],
		serverWriteIV:  p[88:104],
	}
}
