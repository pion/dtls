package dtls

import (
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
)

const (
	prfMasterSecretLabel     = "master secret"
	prfKeyExpansionLabel     = "key expansion"
	prfVerifyDataClientLabel = "client finished"
	prfVerifyDataServerLabel = "server finished"

	prfKeyLen = 16
	prfMacLen = 0
	prfIvLen  = 4
)

type encryptionKeys struct {
	masterSecret   []byte
	clientMACKey   []byte
	serverMACKey   []byte
	clientWriteKey []byte
	serverWriteKey []byte
	clientWriteIV  []byte
	serverWriteIV  []byte
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func prfPreMasterSecret(publicKey, privateKey []byte, curve namedCurve) ([]byte, error) {
	if curve != namedCurveX25519 {
		return nil, errInvalidNamedCurve
	}

	var preMasterSecret, fixedWidthPrivateKey, fixedWidthPublicKey [32]byte
	copy(fixedWidthPrivateKey[:], privateKey)
	copy(fixedWidthPublicKey[:], publicKey)

	curve25519.ScalarMult(&preMasterSecret, &fixedWidthPrivateKey, &fixedWidthPublicKey)
	return preMasterSecret[:], nil
}

func prfMasterSecret(preMasterSecret, clientRandom, serverRandom []byte) []byte {
	seed := append(append([]byte(prfMasterSecretLabel), clientRandom...), serverRandom...)
	a0 := seed
	a1 := hmacSHA256(preMasterSecret, a0)
	a2 := hmacSHA256(preMasterSecret, a1)
	p1 := hmacSHA256(preMasterSecret, append(a1, seed...))
	p2 := hmacSHA256(preMasterSecret, append(a2, seed...))

	return append(p1, p2[:16]...)
}

func prfEncryptionKeys(masterSecret, clientRandom, serverRandom []byte) *encryptionKeys {
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
	keyMaterial := append(append(append(p1, p2...), p3...), p4...)

	clientMACKey := keyMaterial[:prfMacLen]
	keyMaterial = keyMaterial[prfMacLen:]

	serverMACKey := keyMaterial[:prfMacLen]
	keyMaterial = keyMaterial[prfMacLen:]

	clientWriteKey := keyMaterial[:prfKeyLen]
	keyMaterial = keyMaterial[prfKeyLen:]

	serverWriteKey := keyMaterial[:prfKeyLen]
	keyMaterial = keyMaterial[prfKeyLen:]

	clientWriteIV := keyMaterial[:prfIvLen]
	keyMaterial = keyMaterial[prfIvLen:]

	serverWriteIV := keyMaterial[:prfIvLen]

	return &encryptionKeys{
		masterSecret:   masterSecret,
		clientMACKey:   clientMACKey,
		serverMACKey:   serverMACKey,
		clientWriteKey: clientWriteKey,
		serverWriteKey: serverWriteKey,
		clientWriteIV:  clientWriteIV,
		serverWriteIV:  serverWriteIV,
	}
}

func prfVerifyData(masterSecret, handshakeBodies []byte, label string) []byte {
	h := sha256.New()
	h.Write(handshakeBodies)

	seed := append([]byte(label), h.Sum(nil)...)
	a0 := seed
	a1 := hmacSHA256(masterSecret, a0)
	p1 := hmacSHA256(masterSecret, append(a1, seed...))
	return p1[:12]
}

func prfVerifyDataClient(masterSecret, handshakeBodies []byte) []byte {
	return prfVerifyData(masterSecret, handshakeBodies, prfVerifyDataClientLabel)
}

func prfVerifyDataServer(masterSecret, handshakeBodies []byte) []byte {
	return prfVerifyData(masterSecret, handshakeBodies, prfVerifyDataServerLabel)
}
