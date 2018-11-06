package dtls

import "golang.org/x/crypto/curve25519"

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
	return nil
}

func prfEncryptionKeys() (e encryptionKeys) {
	return e
}
