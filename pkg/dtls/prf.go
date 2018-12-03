package dtls

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math"

	"golang.org/x/crypto/curve25519"
)

const (
	prfMasterSecretLabel     = "master secret"
	prfKeyExpansionLabel     = "key expansion"
	prfVerifyDataClientLabel = "client finished"
	prfVerifyDataServerLabel = "server finished"

	prfKeyLen     = 16
	prfMacLen     = 0
	prfIvLen      = 4
	hmacSHA256Len = 32
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

func (e *encryptionKeys) String() string {
	return fmt.Sprintf(`encryptionKeys:
- masterSecret: %#v
- clientMACKey: %#v
- serverMACKey: %#v
- clientWriteKey: %#v
- serverWriteKey: %#v
- clientWriteIV: %#v
- serverWriteIV: %#v
`,
		e.masterSecret,
		e.clientMACKey,
		e.serverMACKey,
		e.clientWriteKey,
		e.serverWriteKey,
		e.clientWriteIV,
		e.serverWriteIV)
}

func prfPreMasterSecret(publicKey, privateKey []byte, curve namedCurve) ([]byte, error) {
	switch curve {
	case namedCurveX25519:
		var preMasterSecret, fixedWidthPrivateKey, fixedWidthPublicKey [32]byte
		copy(fixedWidthPrivateKey[:], privateKey)
		copy(fixedWidthPublicKey[:], publicKey)

		curve25519.ScalarMult(&preMasterSecret, &fixedWidthPrivateKey, &fixedWidthPublicKey)
		return preMasterSecret[:], nil
	case namedCurveP256:
		x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
		if x == nil || y == nil {
			return nil, errInvalidNamedCurve
		}

		curve := elliptic.P256()
		result, _ := curve.ScalarMult(x, y, privateKey)
		preMasterSecret := make([]byte, (curve.Params().BitSize+7)>>3)
		resultBytes := result.Bytes()
		copy(preMasterSecret[len(preMasterSecret)-len(resultBytes):], resultBytes)
		return preMasterSecret, nil
	}

	return nil, errInvalidNamedCurve
}

//  This PRF with the SHA-256 hash function is used for all cipher suites
//  defined in this document and in TLS documents published prior to this
//  document when TLS 1.2 is negotiated.  New cipher suites MUST explicitly
//  specify a PRF and, in general, SHOULD use the TLS PRF with SHA-256 or a
//  stronger standard hash function.
//
//     P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
//                            HMAC_hash(secret, A(2) + seed) +
//                            HMAC_hash(secret, A(3) + seed) + ...
//
//  A() is defined as:
//
//     A(0) = seed
//     A(i) = HMAC_hash(secret, A(i-1))
//
//  P_hash can be iterated as many times as necessary to produce the
//  required quantity of data.  For example, if P_SHA256 is being used to
//  create 80 bytes of data, it will have to be iterated three times
//  (through A(3)), creating 96 bytes of output data; the last 16 bytes
//  of the final iteration will then be discarded, leaving 80 bytes of
//  output data.
//
// https://tools.ietf.org/html/rfc4346w
func prfPHash(secret, seed []byte, requestedLength int) ([]byte, error) {
	hmacSHA256 := func(key, data []byte) ([]byte, error) {
		mac := hmac.New(sha256.New, key)
		if _, err := mac.Write(data); err != nil {
			return nil, err
		}
		return mac.Sum(nil), nil
	}

	var err error
	lastRound := seed
	out := []byte{}

	iterations := int(math.Ceil(float64(requestedLength) / hmacSHA256Len))
	for i := 0; i < iterations; i++ {
		lastRound, err = hmacSHA256(secret, lastRound)
		if err != nil {
			return nil, err
		}
		withSecret, err := hmacSHA256(secret, append(lastRound, seed...))
		if err != nil {
			return nil, err
		}
		out = append(out, withSecret...)
	}

	return out[:requestedLength], nil
}

func prfMasterSecret(preMasterSecret, clientRandom, serverRandom []byte) ([]byte, error) {
	seed := append(append([]byte(prfMasterSecretLabel), clientRandom...), serverRandom...)
	return prfPHash(preMasterSecret, seed, 48)
}

func prfEncryptionKeys(masterSecret, clientRandom, serverRandom []byte) (*encryptionKeys, error) {
	seed := append(append([]byte(prfKeyExpansionLabel), serverRandom...), clientRandom...)
	keyMaterial, err := prfPHash(masterSecret, seed, 128)
	if err != nil {
		return nil, err
	}

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
	}, nil
}

func prfVerifyData(masterSecret, handshakeBodies []byte, label string) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(handshakeBodies); err != nil {
		return nil, err
	}

	seed := append([]byte(label), h.Sum(nil)...)
	return prfPHash(masterSecret, seed, 12)
}

func prfVerifyDataClient(masterSecret, handshakeBodies []byte) ([]byte, error) {
	return prfVerifyData(masterSecret, handshakeBodies, prfVerifyDataClientLabel)
}

func prfVerifyDataServer(masterSecret, handshakeBodies []byte) ([]byte, error) {
	return prfVerifyData(masterSecret, handshakeBodies, prfVerifyDataServerLabel)
}
