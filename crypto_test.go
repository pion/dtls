// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/stretchr/testify/assert"
)

// RSA-PSS certificate with id-RSASSA-PSS OID (1.2.840.113549.1.1.10)
// Generated with:
//
//	openssl genpkey -algorithm RSA-PSS -out rsa_pss_key.pem -pkeyopt rsa_keygen_bits:2048
//	openssl req -new -x509 -key rsa_pss_key.pem -out rsa_pss_cert.pem -days 365 -subj "/CN=RSA-PSS-Test"
//
// Note: Go's x509.CreateCertificate does not support creating RSA-PSS certificates,
// and x509.ParsePKCS8PrivateKey cannot parse RSA-PSS private keys (fails with
// "PKCS#8 wrapping contained private key with unknown algorithm: 1.2.840.113549.1.1.10").
// Therefore we use this cert for OID validation testing only.
//
// nolint: gosec
const rsaPSSCertificate = `
-----BEGIN CERTIFICATE-----
MIIDdTCCAimgAwIBAgIUOvVXWgzlj9KVp4TQe+ZATB3PkvswQQYJKoZIhvcNAQEK
MDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEF
AKIDAgEgMBcxFTATBgNVBAMMDFJTQS1QU1MtVGVzdDAeFw0yNjAxMjQwNDE1MzFa
Fw0yNzAxMjQwNDE1MzFaMBcxFTATBgNVBAMMDFJTQS1QU1MtVGVzdDCCASAwCwYJ
KoZIhvcNAQEKA4IBDwAwggEKAoIBAQCpwVkHm2eU336pNtW7VYuu7nWUkSZxr9Oz
DAQrZbLsdcSeWj/sSe37/EPmtQrH8f8mK7OR7mY1DrodHyAqyGeeHIwTaAMdrrMX
X0RiPbid7w6MU3QZ1q5Hp8IAf8sLrQofchFRLDw6XkMcI4hbWtVJ9GwZiOO2gpDk
uS7SBLEiEzKHme+UzPMFUa2xCypYd/bpO0F+h9vtPDFTCRfK6EFf7mb/QAl1UwfO
Xq5+hMMiKWyhK2OIKhYc98k7eV7nlC4rz5tMY2v1tUJA6/fAZEmAREVE740hxmkN
qN5Enm5tF/ipROPbmQnyCkwtZxKTLi0tz8RTq7lZXRoQr9fo/6ufAgMBAAGjUzBR
MB0GA1UdDgQWBBRpdc2ssJhWnWTm4DPJLW3aDy71WTAfBgNVHSMEGDAWgBRpdc2s
sJhWnWTm4DPJLW3aDy71WTAPBgNVHRMBAf8EBTADAQH/MEEGCSqGSIb3DQEBCjA0
oA8wDQYJYIZIAWUDBAIBBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAIBBQCi
AwIBIAOCAQEATkolVgnlASfTEvMElGmrLTRVPBovk7ZCpER+/H316xswuUDWKn9t
BUhSCYinj5yywgwgx4sErnB5YkB+SR2kkE8WMAU0SNTh2kLUr4TrdqM1o0S5hGQT
awGCPIWZjip3V0TeAqC4sWTgdy2EBYPEJ0AZGm50/yJlWiOzsdDbzceKjremCxLF
Qgkrd/H9mRfIsybvQZ0SbhCWTbNiGpv+O3q4rJ8l3FiaNc9xt+9/FbzeRIipmVb3
ACeCkdjZt/3rjb/tZRHcURgXYi2109wQOaIE5tAQYFCvaKp3HNdWGU1K5+AO0SIY
k2mwB2RsEXa29/Xzj1eMyG33CDgo55AtDw==
-----END CERTIFICATE-----
`

// nolint: gosec
const rawPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxIA2BrrnR2sIlATsp7aRBD/3krwZ7vt9dNeoDQAee0s6SuYP
6MBx/HPnAkwNvPS90R05a7pwRkoT6Ur4PfPhCVlUe8lV+0Eto3ZSEeHz3HdsqlM3
bso67L7Dqrc7MdVstlKcgJi8yeAoGOIL9/igOv0XBFCeznm9nznx6mnsR5cugw+1
ypXelaHmBCLV7r5SeVSh57+KhvZGbQ2fFpUaTPegRpJZXBNS8lSeWvtOv9d6N5UB
ROTAJodMZT5AfX0jB0QB9IT/0I96H6BSENH08NXOeXApMuLKvnAf361rS7cRAfRL
rWZqERMP4u6Cnk0Cnckc3WcW27kGGIbtwbqUIQIDAQABAoIBAGF7OVIdZp8Hejn0
N3L8HvT8xtUEe9kS6ioM0lGgvX5s035Uo4/T6LhUx0VcdXRH9eLHnLTUyN4V4cra
ZkxVsE3zAvZl60G6E+oDyLMWZOP6Wu4kWlub9597A5atT7BpMIVCdmFVZFLB4SJ3
AXkC3nplFAYP+Lh1rJxRIrIn2g+pEeBboWbYA++oDNuMQffDZaokTkJ8Bn1JZYh0
xEXKY8Bi2Egd5NMeZa1UFO6y8tUbZfwgVs6Enq5uOgtfayq79vZwyjj1kd29MBUD
8g8byV053ZKxbUOiOuUts97eb+fN3DIDRTcT2c+lXt/4C54M1FclJAbtYRK/qwsl
pYWKQAECgYEA4ZUbqQnTo1ICvj81ifGrz+H4LKQqe92Hbf/W51D/Umk2kP702W22
HP4CvrJRtALThJIG9m2TwUjl/WAuZIBrhSAbIvc3Fcoa2HjdRp+sO5U1ueDq7d/S
Z+PxRI8cbLbRpEdIaoR46qr/2uWZ943PHMv9h4VHPYn1w8b94hwD6vkCgYEA3v87
mFLzyM9ercnEv9zHMRlMZFQhlcUGQZvfb8BuJYl/WogyT6vRrUuM0QXULNEPlrin
mBQTqc1nCYbgkFFsD2VVt1qIyiAJsB9MD1LNV6YuvE7T2KOSadmsA4fa9PUqbr71
hf3lTTq+LeR09LebO7WgSGYY+5YKVOEGpYMR1GkCgYEAxPVQmk3HKHEhjgRYdaG5
lp9A9ZE8uruYVJWtiHgzBTxx9TV2iST+fd/We7PsHFTfY3+wbpcMDBXfIVRKDVwH
BMwchXH9+Ztlxx34bYJaegd0SmA0Hw9ugWEHNgoSEmWpM1s9wir5/ELjc7dGsFtz
uzvsl9fpdLSxDYgAAdzeGtkCgYBAzKIgrVox7DBzB8KojhtD5ToRnXD0+H/M6OKQ
srZPKhlb0V/tTtxrIx0UUEFLlKSXA6mPw6XDHfDnD86JoV9pSeUSlrhRI+Ysy6tq
eIE7CwthpPZiaYXORHZ7wCqcK/HcpJjsCs9rFbrV0yE5S3FMdIbTAvgXg44VBB7O
UbwIoQKBgDuY8gSrA5/A747wjjmsdRWK4DMTMEV4eCW1BEP7Tg7Cxd5n3xPJiYhr
nhLGN+mMnVIcv2zEMS0/eNZr1j/0BtEdx+3IC6Eq+ONY0anZ4Irt57/5QeKgKn/L
JPhfPySIPG4UmwE4gW8t79vfOKxnUu2fDD1ZXUYopan6EckACNH/
-----END RSA PRIVATE KEY-----
`

func TestGenerateKeySignature(t *testing.T) {
	block, _ := pem.Decode([]byte(rawPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	clientRandom := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	serverRandom := []byte{
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	}
	publicKey := []byte{
		0x20, 0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10,
		0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15,
	}
	expectedSignature := []byte{
		0x6f, 0x47, 0x97, 0x85, 0xcc, 0x76, 0x50, 0x93, 0xbd, 0xe2, 0x6a, 0x69, 0x0b, 0xc3, 0x03, 0xd1, 0xb7, 0xe4,
		0xab, 0x88, 0x7b, 0xa6, 0x52, 0x80, 0xdf, 0xaa, 0x25, 0x7a, 0xdb, 0x29, 0x32, 0xe4, 0xd8, 0x28, 0x28, 0xb3,
		0xe8, 0x04, 0x3c, 0x38, 0x16, 0xfc, 0x78, 0xe9, 0x15, 0x7b, 0xc5, 0xbd, 0x7d, 0xfc, 0xcd, 0x83, 0x00, 0x57,
		0x4a, 0x3c, 0x23, 0x85, 0x75, 0x6b, 0x37, 0xd5, 0x89, 0x72, 0x73, 0xf0, 0x44, 0x8c, 0x00, 0x70, 0x1f, 0x6e,
		0xa2, 0x81, 0xd0, 0x09, 0xc5, 0x20, 0x36, 0xab, 0x23, 0x09, 0x40, 0x1f, 0x4d, 0x45, 0x96, 0x62, 0xbb, 0x81,
		0xb0, 0x30, 0x72, 0xad, 0x3a, 0x0a, 0xac, 0x31, 0x63, 0x40, 0x52, 0x0a, 0x27, 0xf3, 0x34, 0xde, 0x27, 0x7d,
		0xb7, 0x54, 0xff, 0x0f, 0x9f, 0x5a, 0xfe, 0x07, 0x0f, 0x4e, 0x9f, 0x53, 0x04, 0x34, 0x62, 0xf4, 0x30, 0x74,
		0x83, 0x35, 0xfc, 0xe4, 0x7e, 0xbf, 0x5a, 0xc4, 0x52, 0xd0, 0xea, 0xf9, 0x61, 0x4e, 0xf5, 0x1c, 0x0e, 0x58,
		0x02, 0x71, 0xfb, 0x1f, 0x34, 0x55, 0xe8, 0x36, 0x70, 0x3c, 0xc1, 0xcb, 0xc9, 0xb7, 0xbb, 0xb5, 0x1c, 0x44,
		0x9a, 0x6d, 0x88, 0x78, 0x98, 0xd4, 0x91, 0x2e, 0xeb, 0x98, 0x81, 0x23, 0x30, 0x73, 0x39, 0x43, 0xd5, 0xbb,
		0x70, 0x39, 0xba, 0x1f, 0xdb, 0x70, 0x9f, 0x91, 0x83, 0x56, 0xc2, 0xde, 0xed, 0x17, 0x6d, 0x2c, 0x3e, 0x21,
		0xea, 0x36, 0xb4, 0x91, 0xd8, 0x31, 0x05, 0x60, 0x90, 0xfd, 0xc6, 0x74, 0xa9, 0x7b, 0x18, 0xfc, 0x1c, 0x6a,
		0x1c, 0x6e, 0xec, 0xd3, 0xc1, 0xc0, 0x0d, 0x11, 0x25, 0x48, 0x37, 0x3d, 0x45, 0x11, 0xa2, 0x31, 0x14, 0x0a,
		0x66, 0x9f, 0xd8, 0xac, 0x74, 0xa2, 0xcd, 0xc8, 0x79, 0xb3, 0x9e, 0xc6, 0x66, 0x25, 0xcf, 0x2c, 0x87, 0x5e,
		0x5c, 0x36, 0x75, 0x86,
	}

	signature, err := generateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
		key, hash.SHA256, signature.RSA)
	assert.NoError(t, err)
	assert.Equal(t, expectedSignature, signature)
}

func TestRSAPSSSignatureGeneration(t *testing.T) {
	clientRandom := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	serverRandom := []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	publicKey := []byte{0x10, 0x11, 0x12, 0x13}

	// Parse the private key
	block, _ := pem.Decode([]byte(rawPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	// Generate PSS signature
	sig, err := generateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
		key, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	// Verify that PSS signature is different from PKCS#1 v1.5 (PSS is randomized)
	sig2, err := generateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
		key, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
	assert.NoError(t, err)
	// PSS signatures should be different each time due to random salt
	assert.NotEqual(t, sig, sig2)
}

func TestRSAPSSSignatureVerification(t *testing.T) {
	clientRandom := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	serverRandom := []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	publicKey := []byte{0x10, 0x11, 0x12, 0x13}

	// Parse the private key
	block, _ := pem.Decode([]byte(rawPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	// Generate certificate with the public key
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &key.PublicKey,
	}
	rawCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	assert.NoError(t, err)

	// Generate PSS signature
	sig, err := generateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
		key, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
	assert.NoError(t, err)

	// Verify PSS signature
	expectedMsg := valueKeyMessage(clientRandom, serverRandom, publicKey, elliptic.X25519)
	err = verifyKeySignature(expectedMsg, sig, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, [][]byte{rawCert})
	assert.NoError(t, err)

	// Verify that PKCS#1 v1.5 verification fails for PSS signature
	err = verifyKeySignature(expectedMsg, sig, hash.SHA256, signature.RSA, [][]byte{rawCert})
	assert.Error(t, err)
}

func TestRSAPSSVsPKCS1v15(t *testing.T) {
	clientRandom := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	serverRandom := []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	publicKey := []byte{0x10, 0x11, 0x12, 0x13}

	// Parse the private key
	block, _ := pem.Decode([]byte(rawPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	// Generate certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &key.PublicKey,
	}
	rawCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	assert.NoError(t, err)

	expectedMsg := valueKeyMessage(clientRandom, serverRandom, publicKey, elliptic.X25519)

	// Generate and verify PKCS#1 v1.5 signature
	pkcs1Sig, err := generateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
		key, hash.SHA256, signature.RSA)
	assert.NoError(t, err)
	err = verifyKeySignature(expectedMsg, pkcs1Sig, hash.SHA256, signature.RSA, [][]byte{rawCert})
	assert.NoError(t, err)

	// Generate and verify PSS signature
	pssSig, err := generateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
		key, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
	assert.NoError(t, err)
	err = verifyKeySignature(expectedMsg, pssSig, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, [][]byte{rawCert})
	assert.NoError(t, err)

	// Verify cross-verification fails
	err = verifyKeySignature(expectedMsg, pkcs1Sig, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, [][]byte{rawCert})
	assert.Error(t, err, "PKCS#1 v1.5 signature should not verify as PSS")

	err = verifyKeySignature(expectedMsg, pssSig, hash.SHA256, signature.RSA, [][]byte{rawCert})
	assert.Error(t, err, "PSS signature should not verify as PKCS#1 v1.5")
}

func TestRSAPSSRSAEVariants(t *testing.T) {
	clientRandom := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	serverRandom := []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	publicKey := []byte{0x10, 0x11, 0x12, 0x13}

	// Parse the private key
	block, _ := pem.Decode([]byte(rawPrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	// Generate certificate with rsaEncryption OID (standard RSA cert)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &key.PublicKey,
	}
	rawCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	assert.NoError(t, err)

	expectedMsg := valueKeyMessage(clientRandom, serverRandom, publicKey, elliptic.X25519)

	// Test RSA-PSS RSAE variants (work with standard RSA certs)
	// Note: We don't test RSA_PSS_PSS variants here because they require id-RSASSA-PSS OID certs,
	// which Go's x509.CreateCertificate doesn't support creating (and can't parse properly either).
	// OID validation is tested separately in TestCertificateOIDValidation.
	testCases := []struct {
		name     string
		hashAlgo hash.Algorithm
		sigAlgo  signature.Algorithm
	}{
		{"RSA_PSS_RSAE_SHA256", hash.SHA256, signature.RSA_PSS_RSAE_SHA256},
		{"RSA_PSS_RSAE_SHA384", hash.SHA384, signature.RSA_PSS_RSAE_SHA384},
		{"RSA_PSS_RSAE_SHA512", hash.SHA512, signature.RSA_PSS_RSAE_SHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate signature
			sig, err := generateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
				key, tc.hashAlgo, tc.sigAlgo)
			assert.NoError(t, err)
			assert.NotNil(t, sig)
			assert.True(t, len(sig) > 0, "Signature should not be empty")

			// Verify signature
			err = verifyKeySignature(expectedMsg, sig, tc.hashAlgo, tc.sigAlgo, [][]byte{rawCert})
			assert.NoError(t, err, "Signature verification should succeed")

			// Verify IsPSS() returns true
			assert.True(t, tc.sigAlgo.IsPSS(), "Should be identified as PSS algorithm")

			// Verify GetPSSHash() returns correct hash
			assert.Equal(t, tc.hashAlgo, tc.sigAlgo.GetPSSHash(), "Hash extraction should match")
		})
	}
}

func TestCertificateOIDValidation(t *testing.T) {
	clientRandom := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	serverRandom := []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	publicKey := []byte{0x10, 0x11, 0x12, 0x13}

	// Load standard RSA key and cert (has rsaEncryption OID)
	block, _ := pem.Decode([]byte(rawPrivateKey))
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, err)

	rsaEncryptionCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &rsaKey.PublicKey,
	}
	rsaEncryptionCertBytes, err := x509.CreateCertificate(
		rand.Reader, rsaEncryptionCert, rsaEncryptionCert, &rsaKey.PublicKey, rsaKey,
	)
	assert.NoError(t, err)

	// Load RSA-PSS cert (has id-RSASSA-PSS OID)
	// We use a locally generated RSA-PSS cert since Go's x509.CreateCertificate doesn't support creating them.
	// We use the regular RSA key for signing because Go can't parse RSA-PSS private keys either.
	// For OID validation testing, only the cert's OID matters, not which key was used to sign.
	pssCertBlock, _ := pem.Decode([]byte(rsaPSSCertificate))
	pssCertBytes := pssCertBlock.Bytes

	expectedMsg := valueKeyMessage(clientRandom, serverRandom, publicKey, elliptic.X25519)

	t.Run("RSAE_with_rsaEncryption_OID_succeeds", func(t *testing.T) {
		// Generate signature with RSAE algorithm using rsaEncryption cert
		sig, err := generateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
			rsaKey, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
		assert.NoError(t, err)

		// Should succeed: RSAE + rsaEncryption OID is valid per RFC 8446
		err = verifyKeySignature(
			expectedMsg, sig, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, [][]byte{rsaEncryptionCertBytes},
		)
		assert.NoError(t, err)
	})

	t.Run("PSS_with_idRSASSAPSS_OID_succeeds", func(t *testing.T) {
		t.Skip("Go's x509 library cannot extract public key from RSA-PSS certificates (OID 1.2.840.113549.1.1.10)")
		// This test would verify that PSS + id-RSASSA-PSS OID is valid per RFC 8446,
		// but Go's crypto/x509 doesn't fully support parsing RSA-PSS certs.
		// The important validation (that mismatches are rejected) is tested in other cases.
	})

	t.Run("PSS_with_rsaEncryption_OID_fails", func(t *testing.T) {
		// Generate signature with PSS algorithm
		sig, err := generateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
			rsaKey, hash.SHA256, signature.RSA_PSS_PSS_SHA256)
		assert.NoError(t, err)

		// Should fail: PSS algorithm requires id-RSASSA-PSS OID, not rsaEncryption
		err = verifyKeySignature(
			expectedMsg, sig, hash.SHA256, signature.RSA_PSS_PSS_SHA256, [][]byte{rsaEncryptionCertBytes},
		)
		assert.Error(t, err)
		assert.ErrorIs(t, err, errInvalidCertificateOID)
	})

	t.Run("RSAE_with_idRSASSAPSS_OID_fails", func(t *testing.T) {
		// Generate signature with RSAE algorithm
		sig, err := generateKeySignature(clientRandom, serverRandom, publicKey, elliptic.X25519,
			rsaKey, hash.SHA256, signature.RSA_PSS_RSAE_SHA256)
		assert.NoError(t, err)

		// Should fail: RSAE algorithm requires rsaEncryption OID, not id-RSASSA-PSS
		err = verifyKeySignature(expectedMsg, sig, hash.SHA256, signature.RSA_PSS_RSAE_SHA256, [][]byte{pssCertBytes})
		assert.Error(t, err)
		assert.ErrorIs(t, err, errInvalidCertificateOID)
	})
}

func TestValidateCertificateSignatureAlgorithms(t *testing.T) {
	// Helper to create a test certificate with specific signature algorithm
	createTestCert := func(sigAlg x509.SignatureAlgorithm, isCA bool) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:       big.NewInt(1),
			SignatureAlgorithm: sigAlg,
			IsCA:               isCA,
		}
	}

	t.Run("Empty allowed list passes", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.SHA256WithRSA, false),
		}
		err := validateCertificateSignatureAlgorithms(certs, nil)
		assert.NoError(t, err)
	})

	t.Run("Single cert with allowed algorithm passes", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.SHA256WithRSA, false),
			createTestCert(x509.SHA256WithRSA, true), // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.RSA},
		}
		err := validateCertificateSignatureAlgorithms(certs, allowed)
		assert.NoError(t, err)
	})

	t.Run("Single cert with disallowed algorithm fails", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.SHA256WithRSA, false),
			createTestCert(x509.SHA256WithRSA, true), // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA384, Signature: signature.ECDSA}, // Different algorithm
		}
		err := validateCertificateSignatureAlgorithms(certs, allowed)
		assert.ErrorIs(t, err, errInvalidCertificateSignatureAlgorithm)
	})

	t.Run("Root certificate is not validated", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.SHA256WithRSA, false), // Leaf - validated
			createTestCert(x509.SHA384WithRSA, true),  // Root - NOT validated
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.RSA}, // Only allows SHA256
		}
		// Should pass because root (SHA384) is not validated
		err := validateCertificateSignatureAlgorithms(certs, allowed)
		assert.NoError(t, err)
	})

	t.Run("Multi-cert chain with all allowed algorithms passes", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.SHA256WithRSA, false), // Leaf
			createTestCert(x509.SHA384WithRSA, false), // Intermediate
			createTestCert(x509.SHA512WithRSA, true),  // Root (not validated)
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.RSA},
			{Hash: hash.SHA384, Signature: signature.RSA},
			// SHA512 not needed since root is not validated
		}
		err := validateCertificateSignatureAlgorithms(certs, allowed)
		assert.NoError(t, err)
	})

	t.Run("Multi-cert chain with one disallowed intermediate fails", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.SHA256WithRSA, false), // Leaf - allowed
			createTestCert(x509.SHA384WithRSA, false), // Intermediate - NOT allowed
			createTestCert(x509.SHA512WithRSA, true),  // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.RSA}, // Only allows SHA256
		}
		err := validateCertificateSignatureAlgorithms(certs, allowed)
		assert.ErrorIs(t, err, errInvalidCertificateSignatureAlgorithm)
	})

	t.Run("ECDSA certificates", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.ECDSAWithSHA256, false),
			createTestCert(x509.ECDSAWithSHA384, false),
			createTestCert(x509.ECDSAWithSHA512, true), // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.ECDSA},
			{Hash: hash.SHA384, Signature: signature.ECDSA},
		}
		err := validateCertificateSignatureAlgorithms(certs, allowed)
		assert.NoError(t, err)
	})

	t.Run("RSA-PSS certificates", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.SHA256WithRSAPSS, false),
			createTestCert(x509.SHA384WithRSAPSS, true), // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.RSA},
		}
		err := validateCertificateSignatureAlgorithms(certs, allowed)
		assert.NoError(t, err)
	})

	t.Run("Ed25519 certificates", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.PureEd25519, false),
			createTestCert(x509.PureEd25519, true), // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.None, Signature: signature.Ed25519},
		}
		err := validateCertificateSignatureAlgorithms(certs, allowed)
		assert.NoError(t, err)
	})

	t.Run("Unsupported certificate algorithm", func(t *testing.T) {
		certs := []*x509.Certificate{
			createTestCert(x509.MD5WithRSA, false), // MD5 not supported
			createTestCert(x509.SHA256WithRSA, true),
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA256, Signature: signature.RSA},
		}
		err := validateCertificateSignatureAlgorithms(certs, allowed)
		assert.Error(t, err)
		// Should error from FromCertificate, not from algorithm mismatch
	})

	t.Run("Single cert chain does not validate", func(t *testing.T) {
		// Single cert is treated as self-signed root, which is not validated
		certs := []*x509.Certificate{
			createTestCert(x509.SHA256WithRSA, true), // Root
		}
		allowed := []signaturehash.Algorithm{
			{Hash: hash.SHA384, Signature: signature.ECDSA}, // Different algorithm
		}
		// Should pass because single root cert is not validated
		err := validateCertificateSignatureAlgorithms(certs, allowed)
		assert.NoError(t, err)
	})
}
