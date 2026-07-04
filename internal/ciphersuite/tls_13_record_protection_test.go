// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20"
)

type recordProtection13TestCase struct {
	name                       string
	suite                      tls13RecordProtectionSuite
	keyLen                     int
	tagLen                     int
	expectedSequenceNumberMask func(t *testing.T, sequenceNumberKey, encryptedRecord []byte) []byte
}

type tls13RecordProtectionSuite interface {
	CipherSuiteTLS13
	newRecordProtection(localTrafficSecret, remoteTrafficSecret []byte) (*recordProtection13, error)
}

func recordProtection13TestCases() []recordProtection13TestCase {
	return []recordProtection13TestCase{
		{
			name:                       "TLS_AES_128_GCM_SHA256",
			suite:                      NewTLSAes128GcmSha256(),
			keyLen:                     tls13AES128GCMKeyLen,
			tagLen:                     tls13AESGCMTagLen,
			expectedSequenceNumberMask: expectedAESSequenceNumberMask13,
		},
		{
			name:                       "TLS_AES_256_GCM_SHA384",
			suite:                      NewTLSAes256GcmSha384(),
			keyLen:                     tls13AES256GCMKeyLen,
			tagLen:                     tls13AESGCMTagLen,
			expectedSequenceNumberMask: expectedAESSequenceNumberMask13,
		},
		{
			name:                       "TLS_CHACHA20_POLY1305_SHA256",
			suite:                      NewTLSChacha20Poly1305Sha256(),
			keyLen:                     tls13ChaCha20Poly1305KeyLen,
			tagLen:                     tls13ChaCha20Poly1305TagLen,
			expectedSequenceNumberMask: expectedChaCha20SequenceNumberMask13,
		},
	}
}

func expectedAESSequenceNumberMask13(t *testing.T, sequenceNumberKey, encryptedRecord []byte) []byte {
	t.Helper()

	block, err := aes.NewCipher(sequenceNumberKey)
	require.NoError(t, err)

	expectedMask := make([]byte, aes.BlockSize)
	block.Encrypt(expectedMask, encryptedRecord[:aes.BlockSize])

	return expectedMask
}

func expectedChaCha20SequenceNumberMask13(t *testing.T, sequenceNumberKey, encryptedRecord []byte) []byte {
	t.Helper()

	chacha, err := chacha20.NewUnauthenticatedCipher(sequenceNumberKey, encryptedRecord[4:16])
	require.NoError(t, err)
	chacha.SetCounter(binary.LittleEndian.Uint32(encryptedRecord[:4]))

	expectedMask := make([]byte, tls13ChaCha20BlockLen)
	chacha.XORKeyStream(expectedMask, expectedMask)

	return expectedMask
}

func trafficSecret13(suite tls13RecordProtectionSuite, fill byte) []byte {
	hashFunc := suite.HashFunc()

	return bytes.Repeat([]byte{fill}, hashFunc().Size())
}

func newRecordProtection13TestSuite(t *testing.T, name string) tls13RecordProtectionSuite {
	t.Helper()

	for _, testCase := range recordProtection13TestCases() {
		if testCase.name == name {
			return testCase.suite
		}
	}

	assert.FailNowf(t, "unknown TLS 1.3 test suite", "name: %s", name)

	return nil
}

func mustDecodeHex13(t *testing.T, s string) []byte {
	t.Helper()

	out, err := hex.DecodeString(s)
	require.NoError(t, err)

	return out
}

func tlsAES128GCM13VectorSecrets(t *testing.T) (clientSecret, serverSecret []byte) {
	t.Helper()

	clientSecret = mustDecodeHex13(t,
		"000102030405060708090a0b0c0d0e0f"+
			"101112131415161718191a1b1c1d1e1f",
	)
	serverSecret = mustDecodeHex13(t,
		"202122232425262728292a2b2c2d2e2f"+
			"303132333435363738393a3b3c3d3e3f",
	)

	return clientSecret, serverSecret
}

func tlsAES256GCM13VectorSecrets(t *testing.T) (clientSecret, serverSecret []byte) {
	t.Helper()

	clientSecret = mustDecodeHex13(t,
		"000102030405060708090a0b0c0d0e0f"+
			"101112131415161718191a1b1c1d1e1f"+
			"202122232425262728292a2b2c2d2e2f",
	)
	serverSecret = mustDecodeHex13(t,
		"303132333435363738393a3b3c3d3e3f"+
			"404142434445464748494a4b4c4d4e4f"+
			"505152535455565758595a5b5c5d5e5f",
	)

	return clientSecret, serverSecret
}

func tlsChaCha20Poly1305SHA25613VectorSecrets(t *testing.T) (clientSecret, serverSecret []byte) {
	t.Helper()

	clientSecret = mustDecodeHex13(t,
		"000102030405060708090a0b0c0d0e0f"+
			"101112131415161718191a1b1c1d1e1f",
	)
	serverSecret = mustDecodeHex13(t,
		"202122232425262728292a2b2c2d2e2f"+
			"303132333435363738393a3b3c3d3e3f",
	)

	return clientSecret, serverSecret
}

func requireRecordProtection13(t *testing.T, suite tls13RecordProtectionSuite) *recordProtection13 {
	t.Helper()

	switch s := suite.(type) {
	case *TLSAes128GcmSha256:
		protection, ok := s.getRecordProtection13()
		require.True(t, ok)

		return protection
	case *TLSAes256GcmSha384:
		protection, ok := s.getRecordProtection13()
		require.True(t, ok)

		return protection
	case *TLSChacha20Poly1305Sha256:
		protection, ok := s.getRecordProtection13()
		require.True(t, ok)

		return protection
	default:
		assert.FailNowf(t, "unknown TLS 1.3 test suite", "suite: %T", suite)

		return nil
	}
}

type tls13KnownVector struct {
	name                         string
	suite                        func() tls13RecordProtectionSuite
	secrets                      func(t *testing.T) (clientSecret, serverSecret []byte)
	keyLen                       int
	plaintext                    string
	expectedClientKey            string
	expectedClientIV             string
	expectedClientSequenceNumber string
	expectedServerKey            string
	expectedServerIV             string
	expectedServerSequenceNumber string
	expectedNonce                string
	expectedAdditionalData       string
	expectedEncryptedRecord      string
	expectedSequenceNumberMask   string
	expectedMaskedSequenceNumber uint16
	expectedMaskedRaw            string
}

func tls13KnownVectors() []tls13KnownVector {
	return []tls13KnownVector{
		{
			name:                         "TLS_AES_128_GCM_SHA256",
			suite:                        func() tls13RecordProtectionSuite { return NewTLSAes128GcmSha256() },
			secrets:                      tlsAES128GCM13VectorSecrets,
			keyLen:                       tls13AES128GCMKeyLen,
			plaintext:                    "dtls13 aes-128-gcm vector",
			expectedClientKey:            "cc95abc258d309424ddbf7cba68bd77e",
			expectedClientIV:             "6d3299305dd209fc865cf8f1",
			expectedClientSequenceNumber: "c5b1a0649ea4fdafbe7e256665068222",
			expectedServerKey:            "18e38156d5a877f3114a359c90cf6b1c",
			expectedServerIV:             "0fc4773203e01ccd271e629b",
			expectedServerSequenceNumber: "65a419e0a1eda1c3850853fa556adee4",
			expectedNonce:                "6d3299305dd30bff8259fef6",
			expectedAdditionalData:       "3fcafebabe0607002a",
			expectedEncryptedRecord: "82bacfceae1035329372dbcbdce0240faf434e68077fb4df25edc71ddd89db18" +
				"b510ccd2518b77499d7e",
			expectedSequenceNumberMask:   "adc05ac9d6be3e1570d34d94457bdb31",
			expectedMaskedSequenceNumber: 0xabc7,
			expectedMaskedRaw: "3fcafebabeabc7002a82bacfceae1035329372dbcbdce0240faf434e68077fb4df25edc71ddd89db18" +
				"b510ccd2518b77499d7e",
		},
		{
			name:                         "TLS_AES_256_GCM_SHA384",
			suite:                        func() tls13RecordProtectionSuite { return NewTLSAes256GcmSha384() },
			secrets:                      tlsAES256GCM13VectorSecrets,
			keyLen:                       tls13AES256GCMKeyLen,
			plaintext:                    "dtls13 aes-256-gcm vector",
			expectedClientKey:            "d6732c55efc102933ffe3af6922bdb7fe44d18f2b7307173758bfeb457a6f9bb",
			expectedClientIV:             "8ae6b315daa064c6dfa5f10a",
			expectedClientSequenceNumber: "fc6f78156052e019518fb3ea0d77c796ca2da8796cc26b8e42c5b5395a72af1d",
			expectedServerKey:            "7c523cc53469c11fd6ca9acb78a0bf2bbe34f7779dca7ab75eb6fd7d2dc0d667",
			expectedServerIV:             "52c85dfce33da09b62295ad7",
			expectedServerSequenceNumber: "9a7ed1d037e961ad1ee02fde1315f29ebfd2fc8f3c823726064b93f0e9964569",
			expectedNonce:                "8ae6b315daa166c5dba0f70d",
			expectedAdditionalData:       "3fcafebabe0607002a",
			expectedEncryptedRecord: "799936beea392e94f73b56ad19e96f5ff607481e8abf5aa6895414e222eea46" +
				"b4e2385ac65b6fc516ede",
			expectedSequenceNumberMask:   "cdefbbfbc4863ce5602213c2290c989e",
			expectedMaskedSequenceNumber: 0xcbe8,
			expectedMaskedRaw: "3fcafebabecbe8002a799936beea392e94f73b56ad19e96f5ff607481e8abf5aa6895414e222eea46" +
				"b4e2385ac65b6fc516ede",
		},
		{
			name:                         "TLS_CHACHA20_POLY1305_SHA256",
			suite:                        func() tls13RecordProtectionSuite { return NewTLSChacha20Poly1305Sha256() },
			secrets:                      tlsChaCha20Poly1305SHA25613VectorSecrets,
			keyLen:                       tls13ChaCha20Poly1305KeyLen,
			plaintext:                    "dtls13 chacha20-poly1305 vector",
			expectedClientKey:            "fa36130205a96cbeb292e37361db797a5292833e60912c992462e04b0eba0ecd",
			expectedClientIV:             "6d3299305dd209fc865cf8f1",
			expectedClientSequenceNumber: "534890654f2b1ca72683f148cdbae6a98ffeaaad7e23fc9e693486e2a92b6892",
			expectedServerKey:            "764d73625579da13dbf400345a3a28f64e1fd7d755ec9b6e1f7ade12c2b7b735",
			expectedServerIV:             "0fc4773203e01ccd271e629b",
			expectedServerSequenceNumber: "93360cb9d6b073a87e187ca4398acb6adf02f76aa7f485b76e18e07eba60d867",
			expectedNonce:                "6d3299305dd30bff8259fef6",
			expectedAdditionalData:       "3fcafebabe06070030",
			expectedEncryptedRecord: "69f043b34d3e3b856ce115bab907b93c384fe7d6375a38b00d864a1562eedd91" +
				"f386a79a681d216cd5ff74d73b419b97",
			expectedSequenceNumberMask: "2e70bc45d477904ca0053b5321f731eaa5abe10c14ddbefe797decfe78d9c802" +
				"4d8fce70b14fef48c53d095eb737c95812be77d25a1280c60a68d4a8600680c3",
			expectedMaskedSequenceNumber: 0x2877,
			expectedMaskedRaw: "3fcafebabe2877003069f043b34d3e3b856ce115bab907b93c384fe7d6375a38b00d864a1562eedd91" +
				"f386a79a681d216cd5ff74d73b419b97",
		},
	}
}

func TestTLS13RecordProtectionKnownVectors(t *testing.T) {
	for _, vector := range tls13KnownVectors() {
		t.Run(vector.name, func(t *testing.T) {
			assertTLS13RecordProtectionKnownVector(t, vector)
		})
	}
}

func assertTLS13RecordProtectionKnownVector(t *testing.T, vector tls13KnownVector) {
	t.Helper()

	suite := vector.suite()
	clientSecret, serverSecret := vector.secrets(t)
	sequenceNumber := uint64(0x0001020304050607)
	plaintext := []byte(vector.plaintext)

	clientKeys, err := deriveRecordTrafficKeys13(suite.HashFunc(), clientSecret, vector.keyLen)
	require.NoError(t, err)
	assertTLS13TrafficKeys(t, clientKeys,
		vector.expectedClientKey,
		vector.expectedClientIV,
		vector.expectedClientSequenceNumber,
	)

	serverKeys, err := deriveRecordTrafficKeys13(suite.HashFunc(), serverSecret, vector.keyLen)
	require.NoError(t, err)
	assertTLS13TrafficKeys(t, serverKeys,
		vector.expectedServerKey,
		vector.expectedServerIV,
		vector.expectedServerSequenceNumber,
	)

	protection, err := suite.newRecordProtection(clientSecret, serverSecret)
	require.NoError(t, err)
	peerProtection, err := suite.newRecordProtection(serverSecret, clientSecret)
	require.NoError(t, err)

	nonce, err := recordNonce13(protection.local.iv, sequenceNumber)
	require.NoError(t, err)
	assert.Equal(t, mustDecodeHex13(t, vector.expectedNonce), nonce)

	record, err := protection.seal(
		recordlayer.UnifiedHeader{
			ConnectionID:   []byte{0xca, 0xfe, 0xba, 0xbe},
			SequenceNumber: uint16(sequenceNumber), //nolint:gosec // G115
			EpochLow:       3,
		},
		sequenceNumber,
		protocol.ContentTypeApplicationData,
		plaintext,
	)
	require.NoError(t, err)

	assert.Equal(t, uint8(3), record.Header.EpochLow)
	assert.True(t, record.Header.SeqBit)
	assert.True(t, record.Header.LengthBit)
	assert.Equal(t, uint16(0x0607), record.Header.SequenceNumber)
	expectedEncryptedRecord := mustDecodeHex13(t, vector.expectedEncryptedRecord)
	assert.Equal(t, uint16(len(expectedEncryptedRecord)), record.Header.Length) //nolint:gosec // G115

	additionalData, err := record.Header.Marshal()
	require.NoError(t, err)
	assert.Equal(t, mustDecodeHex13(t, vector.expectedAdditionalData), additionalData)
	assert.Equal(t, expectedEncryptedRecord, record.EncryptedRecord)

	mask, err := protection.local.sequenceNumberMask(record.EncryptedRecord)
	require.NoError(t, err)
	assert.Equal(t, mustDecodeHex13(t, vector.expectedSequenceNumberMask), mask)

	maskedHeader := record.Header
	require.NoError(t, applySequenceNumberMask13(&maskedHeader, mask))
	assert.Equal(t, vector.expectedMaskedSequenceNumber, maskedHeader.SequenceNumber)

	maskedRaw, err := (&recordlayer.CiphertextRecord13{
		Header:          maskedHeader,
		EncryptedRecord: record.EncryptedRecord,
	}).Marshal()
	require.NoError(t, err)
	assert.Equal(t, mustDecodeHex13(t, vector.expectedMaskedRaw), maskedRaw)

	innerPlaintext, err := peerProtection.open(record.Header, sequenceNumber, record.EncryptedRecord)
	require.NoError(t, err)
	assert.Equal(t, plaintext, innerPlaintext.Content)
	assert.Equal(t, protocol.ContentTypeApplicationData, innerPlaintext.RealType)
	assert.Equal(t, uint(0), innerPlaintext.Zeros)
}

func assertTLS13TrafficKeys(
	t *testing.T,
	keys recordTrafficKeys13,
	expectedKey, expectedIV, expectedSequenceNumberKey string,
) {
	t.Helper()

	assert.Equal(t, mustDecodeHex13(t, expectedKey), keys.key)
	assert.Equal(t, mustDecodeHex13(t, expectedIV), keys.iv)
	assert.Equal(t, mustDecodeHex13(t, expectedSequenceNumberKey), keys.sequenceNumberKey)
}

func TestTLS13SuiteSealOpenKnownVectors(t *testing.T) {
	for _, vector := range tls13KnownVectors() {
		t.Run(vector.name, func(t *testing.T) {
			assertTLS13SuiteSealOpenKnownVector(t, vector)
		})
	}
}

func assertTLS13SuiteSealOpenKnownVector(t *testing.T, vector tls13KnownVector) {
	t.Helper()

	clientSuite := vector.suite()
	serverSuite := vector.suite()
	clientSecret, serverSecret := vector.secrets(t)
	sequenceNumber := uint64(0x0001020304050607)
	plaintext := []byte(vector.plaintext)

	require.NoError(t, clientSuite.InitFromTrafficSecrets(clientSecret, serverSecret, true))
	require.NoError(t, serverSuite.InitFromTrafficSecrets(clientSecret, serverSecret, false))

	record, err := clientSuite.Seal(
		recordlayer.UnifiedHeader{
			ConnectionID: []byte{0xca, 0xfe, 0xba, 0xbe},
			EpochLow:     3,
		},
		sequenceNumber,
		protocol.ContentTypeApplicationData,
		plaintext,
	)
	require.NoError(t, err)

	assert.Equal(t, vector.expectedMaskedSequenceNumber, record.Header.SequenceNumber)
	expectedEncryptedRecord := mustDecodeHex13(t, vector.expectedEncryptedRecord)
	assert.Equal(t, uint16(len(expectedEncryptedRecord)), record.Header.Length) //nolint:gosec // G115
	assert.True(t, record.Header.SeqBit)
	assert.True(t, record.Header.LengthBit)
	assert.Equal(t, expectedEncryptedRecord, record.EncryptedRecord)

	raw, err := record.Marshal()
	require.NoError(t, err)
	assert.Equal(t, mustDecodeHex13(t, vector.expectedMaskedRaw), raw)

	innerPlaintext, err := serverSuite.Open(record.Header, sequenceNumber, record.EncryptedRecord)
	require.NoError(t, err)
	assert.Equal(t, plaintext, innerPlaintext.Content)
	assert.Equal(t, protocol.ContentTypeApplicationData, innerPlaintext.RealType)
}

func TestTLS13OpenRejectsKnownVectorMutations(t *testing.T) {
	for _, vector := range tls13KnownVectors() {
		t.Run(vector.name, func(t *testing.T) {
			assertTLS13OpenRejectsKnownVectorMutations(t, vector)
		})
	}
}

func assertTLS13OpenRejectsKnownVectorMutations(t *testing.T, vector tls13KnownVector) {
	t.Helper()

	suite := vector.suite()
	clientSecret, serverSecret := vector.secrets(t)
	sequenceNumber := uint64(0x0001020304050607)

	protection, err := suite.newRecordProtection(clientSecret, serverSecret)
	require.NoError(t, err)
	peerProtection, err := suite.newRecordProtection(serverSecret, clientSecret)
	require.NoError(t, err)

	record, err := protection.seal(
		recordlayer.UnifiedHeader{
			ConnectionID:   []byte{0xca, 0xfe, 0xba, 0xbe},
			SequenceNumber: uint16(sequenceNumber), //nolint:gosec // G115
			EpochLow:       3,
		},
		sequenceNumber,
		protocol.ContentTypeApplicationData,
		[]byte(vector.plaintext),
	)
	require.NoError(t, err)

	for _, testCase := range tls13KnownVectorMutationCases(sequenceNumber) {
		t.Run(testCase.name, func(t *testing.T) {
			header := record.Header
			header.ConnectionID = append([]byte(nil), record.Header.ConnectionID...)
			encryptedRecord := append([]byte(nil), record.EncryptedRecord...)

			if testCase.mutateHeader != nil {
				testCase.mutateHeader(&header)
			}
			if testCase.mutateEncrypted != nil {
				testCase.mutateEncrypted(encryptedRecord)
			}

			_, err := peerProtection.open(header, testCase.sequenceNumber, encryptedRecord)
			assert.ErrorIs(t, err, dtlserrors.ErrDecryptPacket)
		})
	}
}

type tls13KnownVectorMutationCase struct {
	name            string
	mutateHeader    func(*recordlayer.UnifiedHeader)
	mutateEncrypted func([]byte)
	sequenceNumber  uint64
}

func tls13KnownVectorMutationCases(sequenceNumber uint64) []tls13KnownVectorMutationCase {
	return []tls13KnownVectorMutationCase{
		{
			name: "header length authenticated",
			mutateHeader: func(header *recordlayer.UnifiedHeader) {
				header.Length ^= 0x0001
			},
			sequenceNumber: sequenceNumber,
		},
		{
			name: "connection id authenticated",
			mutateHeader: func(header *recordlayer.UnifiedHeader) {
				header.ConnectionID[0] ^= 0x80
			},
			sequenceNumber: sequenceNumber,
		},
		{
			name:           "nonce sequence number authenticated",
			sequenceNumber: sequenceNumber + 1,
		},
		{
			name: "ciphertext authenticated",
			mutateEncrypted: func(encryptedRecord []byte) {
				encryptedRecord[0] ^= 0x80
			},
			sequenceNumber: sequenceNumber,
		},
		{
			name: "tag authenticated",
			mutateEncrypted: func(encryptedRecord []byte) {
				encryptedRecord[len(encryptedRecord)-1] ^= 0x01
			},
			sequenceNumber: sequenceNumber,
		},
	}
}

func TestDeriveRecordTrafficKeys13Suites(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			hashFunc := testCase.suite.HashFunc()
			trafficSecret := trafficSecret13(testCase.suite, 0x3c)

			keys, err := deriveRecordTrafficKeys13(hashFunc, trafficSecret, testCase.keyLen)
			require.NoError(t, err)

			require.Len(t, keys.key, testCase.keyLen)
			require.Len(t, keys.iv, tls13AEADWriteIVLen)
			require.Len(t, keys.sequenceNumberKey, testCase.keyLen)

			expectedKey, err := keyschedule.HkdfExpandLabel(
				hashFunc,
				trafficSecret,
				trafficKeyLabel13,
				nil,
				testCase.keyLen,
			)
			require.NoError(t, err)

			expectedIV, err := keyschedule.HkdfExpandLabel(
				hashFunc,
				trafficSecret,
				trafficIVLabel13,
				nil,
				tls13AEADWriteIVLen,
			)
			require.NoError(t, err)

			expectedSequenceNumberKey, err := keyschedule.HkdfExpandLabel(
				hashFunc,
				trafficSecret,
				trafficSequenceNumberKeyLabel13,
				nil,
				testCase.keyLen,
			)
			require.NoError(t, err)

			assert.Equal(t, expectedKey, keys.key)
			assert.Equal(t, expectedIV, keys.iv)
			assert.Equal(t, expectedSequenceNumberKey, keys.sequenceNumberKey)
			assert.NotEqual(t, keys.key, keys.sequenceNumberKey)
		})
	}
}

func TestTLS13CipherSuiteNewRecordProtectionSuites(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			localTrafficSecret := trafficSecret13(testCase.suite, 0x5a)
			remoteTrafficSecret := trafficSecret13(testCase.suite, 0x6b)

			protection, err := testCase.suite.newRecordProtection(localTrafficSecret, remoteTrafficSecret)
			require.NoError(t, err)
			require.NotNil(t, protection.local.aead)
			require.NotNil(t, protection.remote.aead)

			assert.Equal(t, tls13AEADWriteIVLen, protection.local.aead.NonceSize())
			assert.Equal(t, testCase.tagLen, protection.local.aead.Overhead())
			require.Len(t, protection.local.iv, tls13AEADWriteIVLen)
			require.Len(t, protection.remote.iv, tls13AEADWriteIVLen)
			require.Len(t, protection.local.sequenceNumberKey, testCase.keyLen)
			require.Len(t, protection.remote.sequenceNumberKey, testCase.keyLen)
			assert.NotEqual(t, protection.local.iv, protection.remote.iv)
			assert.NotEqual(t, protection.local.sequenceNumberKey, protection.remote.sequenceNumberKey)

			plaintext := []byte("dtls13 record protection")
			additionalData := []byte("synthetic aad")
			nonce := append([]byte(nil), protection.local.iv...)

			ciphertext := protection.local.aead.Seal(nil, nonce, plaintext, additionalData)
			require.Len(t, ciphertext, len(plaintext)+protection.local.aead.Overhead())

			decrypted, err := protection.local.aead.Open(nil, nonce, ciphertext, additionalData)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

func TestTLS13CipherSuiteInitFromTrafficSecrets(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			clientSuite := testCase.suite
			serverSuite := newRecordProtection13TestSuite(t, testCase.name)

			clientSecret := trafficSecret13(testCase.suite, 0xa6)
			serverSecret := trafficSecret13(testCase.suite, 0xb6)

			require.False(t, clientSuite.IsInitialized())
			require.False(t, serverSuite.IsInitialized())

			require.NoError(t, clientSuite.InitFromTrafficSecrets(clientSecret, serverSecret, true))
			require.NoError(t, serverSuite.InitFromTrafficSecrets(clientSecret, serverSecret, false))

			require.True(t, clientSuite.IsInitialized())
			require.True(t, serverSuite.IsInitialized())

			clientProtection := requireRecordProtection13(t, clientSuite)
			serverProtection := requireRecordProtection13(t, serverSuite)
			header := recordlayer.UnifiedHeader{
				SequenceNumber: 0x1234,
				EpochLow:       2,
			}
			sequenceNumber := uint64(0x0102030405060708)
			plaintext := []byte("traffic-secret initialized payload")

			record, err := clientProtection.seal(header, sequenceNumber, protocol.ContentTypeApplicationData, plaintext)
			require.NoError(t, err)

			innerPlaintext, err := serverProtection.open(record.Header, sequenceNumber, record.EncryptedRecord)
			require.NoError(t, err)
			assert.Equal(t, plaintext, innerPlaintext.Content)
			assert.Equal(t, protocol.ContentTypeApplicationData, innerPlaintext.RealType)
		})
	}
}

func TestTLS13CipherSuiteSeal(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			clientSuite := testCase.suite
			serverSuite := newRecordProtection13TestSuite(t, testCase.name)

			clientSecret := trafficSecret13(testCase.suite, 0xa7)
			serverSecret := trafficSecret13(testCase.suite, 0xb7)
			require.NoError(t, clientSuite.InitFromTrafficSecrets(clientSecret, serverSecret, true))
			require.NoError(t, serverSuite.InitFromTrafficSecrets(clientSecret, serverSecret, false))

			sequenceNumber := uint64(0x0102030405061234)
			header := recordlayer.UnifiedHeader{
				SequenceNumber: uint16(sequenceNumber), //nolint:gosec // G115
				EpochLow:       2,
			}
			plaintext := []byte("suite-level seal payload")

			record, err := clientSuite.Seal(header, sequenceNumber, protocol.ContentTypeApplicationData, plaintext)
			require.NoError(t, err)

			require.True(t, record.Header.SeqBit)
			require.True(t, record.Header.LengthBit)
			require.Equal(t, uint16(len(record.EncryptedRecord)), record.Header.Length) //nolint:gosec

			serverProtection := requireRecordProtection13(t, serverSuite)
			mask, err := serverProtection.remote.sequenceNumberMask(record.EncryptedRecord)
			require.NoError(t, err)
			expectedHeaderSequenceNumber := uint16(sequenceNumber & 0xffff) //nolint:gosec // G115
			expectedMaskedSequenceNumber := expectedHeaderSequenceNumber ^ (uint16(mask[0])<<8 | uint16(mask[1]))
			assert.Equal(t, expectedMaskedSequenceNumber, record.Header.SequenceNumber)

			clearHeader := record.Header
			require.NoError(t, applySequenceNumberMask13(&clearHeader, mask))
			assert.Equal(t, expectedHeaderSequenceNumber, clearHeader.SequenceNumber)

			innerPlaintext, err := serverProtection.open(clearHeader, sequenceNumber, record.EncryptedRecord)
			require.NoError(t, err)
			assert.Equal(t, plaintext, innerPlaintext.Content)
			assert.Equal(t, protocol.ContentTypeApplicationData, innerPlaintext.RealType)
		})
	}
}

func TestTLS13CipherSuiteSealRejectsUninitialized(t *testing.T) {
	suite := NewTLSAes128GcmSha256()

	_, err := suite.Seal(
		recordlayer.UnifiedHeader{SequenceNumber: 0x1234, EpochLow: 2},
		0x0102030405061234,
		protocol.ContentTypeApplicationData,
		[]byte("uninitialized"),
	)
	assert.ErrorIs(t, err, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented)
}

func TestTLS13CipherSuiteOpen(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			clientSuite := testCase.suite
			serverSuite := newRecordProtection13TestSuite(t, testCase.name)

			clientSecret := trafficSecret13(testCase.suite, 0xa8)
			serverSecret := trafficSecret13(testCase.suite, 0xb8)
			require.NoError(t, clientSuite.InitFromTrafficSecrets(clientSecret, serverSecret, true))
			require.NoError(t, serverSuite.InitFromTrafficSecrets(clientSecret, serverSecret, false))

			sequenceNumber := uint64(0x0102030405061234)
			plaintext := []byte("suite-level open payload")

			record, err := clientSuite.Seal(
				recordlayer.UnifiedHeader{SequenceNumber: 0xbeef, EpochLow: 2},
				sequenceNumber,
				protocol.ContentTypeApplicationData,
				plaintext,
			)
			require.NoError(t, err)

			innerPlaintext, err := serverSuite.Open(record.Header, sequenceNumber, record.EncryptedRecord)
			require.NoError(t, err)
			assert.Equal(t, plaintext, innerPlaintext.Content)
			assert.Equal(t, protocol.ContentTypeApplicationData, innerPlaintext.RealType)
		})
	}
}

func TestTLS13CipherSuiteOpenRejectsUninitialized(t *testing.T) {
	suite := NewTLSAes128GcmSha256()

	_, err := suite.Open(
		recordlayer.UnifiedHeader{SequenceNumber: 0x1234, EpochLow: 2},
		0x0102030405061234,
		[]byte("uninitialized"),
	)
	assert.ErrorIs(t, err, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented)
}

func TestTLS13CipherSuiteOpenRejectsWrongSequenceNumberLowBits(t *testing.T) {
	suite := NewTLSAes128GcmSha256()
	clientSecret := trafficSecret13(suite, 0xc1)
	serverSecret := trafficSecret13(suite, 0xd1)
	require.NoError(t, suite.InitFromTrafficSecrets(clientSecret, serverSecret, false))

	protection, err := suite.newRecordProtection(clientSecret, serverSecret)
	require.NoError(t, err)

	sequenceNumber := uint64(0x0102030405061234)
	record, err := protection.seal(
		recordlayer.UnifiedHeader{SequenceNumber: uint16(sequenceNumber), EpochLow: 2}, //nolint:gosec // G115
		sequenceNumber,
		protocol.ContentTypeApplicationData,
		[]byte("wrong sequence number"),
	)
	require.NoError(t, err)

	mask, err := protection.local.sequenceNumberMask(record.EncryptedRecord)
	require.NoError(t, err)
	maskedHeader := record.Header
	require.NoError(t, applySequenceNumberMask13(&maskedHeader, mask))

	_, err = suite.Open(maskedHeader, sequenceNumber+1, record.EncryptedRecord)
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidCiphertextHeader)
}

func TestRecordProtection13SealOpenSyntheticTrafficSecret(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			localTrafficSecret := trafficSecret13(testCase.suite, 0xa6)
			remoteTrafficSecret := trafficSecret13(testCase.suite, 0xb6)
			protection, err := testCase.suite.newRecordProtection(localTrafficSecret, remoteTrafficSecret)
			require.NoError(t, err)
			peerProtection, err := testCase.suite.newRecordProtection(remoteTrafficSecret, localTrafficSecret)
			require.NoError(t, err)

			header := recordlayer.UnifiedHeader{
				SequenceNumber: 0x1234,
				EpochLow:       2,
			}
			sequenceNumber := uint64(0x0102030405060708)
			plaintext := []byte("protected dtls13 payload")

			record, err := protection.seal(header, sequenceNumber, protocol.ContentTypeApplicationData, plaintext)
			require.NoError(t, err)

			require.Equal(t, uint16(len(record.EncryptedRecord)), record.Header.Length) //nolint:gosec
			require.True(t, record.Header.LengthBit)
			require.True(t, record.Header.SeqBit)
			require.Len(t, record.EncryptedRecord, len(plaintext)+1+testCase.tagLen)

			innerPlaintext, err := peerProtection.open(record.Header, sequenceNumber, record.EncryptedRecord)
			require.NoError(t, err)

			assert.Equal(t, plaintext, innerPlaintext.Content)
			assert.Equal(t, protocol.ContentTypeApplicationData, innerPlaintext.RealType)
			assert.Equal(t, uint(0), innerPlaintext.Zeros)
		})
	}
}

func TestRecordProtection13SealRejectsOversizedPlaintext(t *testing.T) {
	suite := NewTLSAes128GcmSha256()
	protection, err := suite.newRecordProtection(trafficSecret13(suite, 0xaa), trafficSecret13(suite, 0xab))
	require.NoError(t, err)

	header := recordlayer.UnifiedHeader{SequenceNumber: 0x1234, EpochLow: 2}
	_, err = protection.seal(
		header,
		0x0102030405060708,
		protocol.ContentTypeApplicationData,
		bytes.Repeat([]byte{0x01}, maxDTLSPlaintextRecordLen13),
	)
	require.NoError(t, err)

	_, err = protection.seal(
		header,
		0x0102030405060708,
		protocol.ContentTypeApplicationData,
		bytes.Repeat([]byte{0x01}, maxDTLSPlaintextRecordLen13+1),
	)
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidPacketLength)
}

func TestRecordProtection13OpenRejectsWrongAdditionalData(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			localTrafficSecret := trafficSecret13(testCase.suite, 0xb7)
			remoteTrafficSecret := trafficSecret13(testCase.suite, 0xc7)
			protection, err := testCase.suite.newRecordProtection(localTrafficSecret, remoteTrafficSecret)
			require.NoError(t, err)
			peerProtection, err := testCase.suite.newRecordProtection(remoteTrafficSecret, localTrafficSecret)
			require.NoError(t, err)

			record, err := protection.seal(
				recordlayer.UnifiedHeader{SequenceNumber: 0x4567, EpochLow: 1},
				0x0102030405060708,
				protocol.ContentTypeHandshake,
				[]byte{0x01, 0x02, 0x03},
			)
			require.NoError(t, err)

			record.Header.SequenceNumber ^= 0x0001
			_, err = peerProtection.open(record.Header, 0x0102030405060708, record.EncryptedRecord)
			assert.ErrorIs(t, err, dtlserrors.ErrDecryptPacket)
		})
	}
}

func TestRecordProtection13OpenRejectsWrongSequenceNumber(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			localTrafficSecret := trafficSecret13(testCase.suite, 0xbe)
			remoteTrafficSecret := trafficSecret13(testCase.suite, 0xce)
			protection, err := testCase.suite.newRecordProtection(localTrafficSecret, remoteTrafficSecret)
			require.NoError(t, err)
			peerProtection, err := testCase.suite.newRecordProtection(remoteTrafficSecret, localTrafficSecret)
			require.NoError(t, err)

			record, err := protection.seal(
				recordlayer.UnifiedHeader{SequenceNumber: 0x4567, EpochLow: 1},
				0x0102030405060708,
				protocol.ContentTypeHandshake,
				[]byte{0x01, 0x02, 0x03},
			)
			require.NoError(t, err)

			_, err = peerProtection.open(record.Header, 0x0102030405060709, record.EncryptedRecord)
			assert.ErrorIs(t, err, dtlserrors.ErrDecryptPacket)
		})
	}
}

func TestRecordProtection13SequenceNumberMaskSyntheticTrafficSecret(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			protection, err := testCase.suite.newRecordProtection(
				trafficSecret13(testCase.suite, 0xc8),
				trafficSecret13(testCase.suite, 0xc9),
			)
			require.NoError(t, err)

			record, err := protection.seal(
				recordlayer.UnifiedHeader{SequenceNumber: 0x0102, EpochLow: 3},
				0x1112131415161718,
				protocol.ContentTypeApplicationData,
				[]byte("mask sample source"),
			)
			require.NoError(t, err)

			mask, err := protection.sequenceNumberMask(record.EncryptedRecord)
			require.NoError(t, err)
			expectedMask := testCase.expectedSequenceNumberMask(t, protection.local.sequenceNumberKey, record.EncryptedRecord)

			assert.Equal(t, expectedMask, mask)

			rawHeader, err := record.Header.Marshal()
			require.NoError(t, err)
			maskedHeader := append([]byte(nil), rawHeader...)
			maskedHeader[1] ^= mask[0]
			maskedHeader[2] ^= mask[1]
			assert.NotEqual(t, rawHeader, maskedHeader)

			maskedHeader[1] ^= mask[0]
			maskedHeader[2] ^= mask[1]
			assert.Equal(t, rawHeader, maskedHeader)
		})
	}
}

func TestRecordProtection13SequenceNumberMaskUnmaskRoundTrip(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			localTrafficSecret := trafficSecret13(testCase.suite, 0xcb)
			remoteTrafficSecret := trafficSecret13(testCase.suite, 0xdb)
			protection, err := testCase.suite.newRecordProtection(localTrafficSecret, remoteTrafficSecret)
			require.NoError(t, err)
			peerProtection, err := testCase.suite.newRecordProtection(remoteTrafficSecret, localTrafficSecret)
			require.NoError(t, err)

			sequenceNumber := uint64(0x0102030405062468)
			record, err := protection.seal(
				recordlayer.UnifiedHeader{SequenceNumber: uint16(sequenceNumber), EpochLow: 2}, //nolint:gosec // G115
				sequenceNumber,
				protocol.ContentTypeApplicationData,
				[]byte("mask and unmask round trip"),
			)
			require.NoError(t, err)

			mask, err := protection.local.sequenceNumberMask(record.EncryptedRecord)
			require.NoError(t, err)
			expectedMaskedHeader := record.Header
			require.NoError(t, applySequenceNumberMask13(&expectedMaskedHeader, mask))

			maskedHeader := record.Header
			require.NoError(t, protection.maskLocalSequenceNumber(&maskedHeader, record.EncryptedRecord))
			assert.Equal(t, expectedMaskedHeader, maskedHeader)

			unmaskedHeader := maskedHeader
			require.NoError(t, peerProtection.unmaskRemoteSequenceNumber(&unmaskedHeader, record.EncryptedRecord))
			assert.Equal(t, record.Header, unmaskedHeader)
		})
	}
}

func TestApplySequenceNumberMask13ShortSequenceNumber(t *testing.T) {
	header := recordlayer.UnifiedHeader{
		SequenceNumber: 0xabcd,
		SeqBit:         false,
	}
	require.NoError(t, applySequenceNumberMask13(&header, []byte{0xef}))
	assert.Equal(t, uint16(0x0022), header.SequenceNumber)

	header = recordlayer.UnifiedHeader{
		SequenceNumber: 0xabcd,
		SeqBit:         false,
	}
	err := applySequenceNumberMask13(&header, nil)
	assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)
	assert.Equal(t, uint16(0xabcd), header.SequenceNumber)
}

func TestApplySequenceNumberMask13RejectsInvalidInputs(t *testing.T) {
	err := applySequenceNumberMask13(nil, []byte{0x01, 0x02})
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidCiphertextHeader)

	header := recordlayer.UnifiedHeader{
		SequenceNumber: 0xabcd,
		SeqBit:         true,
	}
	err = applySequenceNumberMask13(&header, []byte{0x01})
	assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)
	assert.Equal(t, uint16(0xabcd), header.SequenceNumber)
}

func TestRecordProtection13SequenceNumberMaskRejectsShortCiphertext(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			protection, err := testCase.suite.newRecordProtection(
				trafficSecret13(testCase.suite, 0xd9),
				trafficSecret13(testCase.suite, 0xda),
			)
			require.NoError(t, err)

			_, err = protection.sequenceNumberMask(bytes.Repeat([]byte{0x01}, tls13SequenceNumberMaskSampleLen-1))
			assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)
		})
	}
}

func TestRecordSequenceNumberMaskChaCha20RFC8439BlockVector(t *testing.T) {
	sequenceNumberKey, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)
	encryptedRecord, err := hex.DecodeString("01000000000000090000004a00000000")
	require.NoError(t, err)

	mask, err := recordSequenceNumberMaskChaCha20Poly1305TLS13(sequenceNumberKey, encryptedRecord)
	require.NoError(t, err)

	expected, err := hex.DecodeString(
		"10f1e7e4d13b5915500fdd1fa32071c4" +
			"c7d1f4c733c068030422aa9ac3d46c4e" +
			"d2826446079faa0914c2d705d98b02a2" +
			"b5129cd1de164eb9cbd083e8a2503c4e",
	)
	require.NoError(t, err)
	assert.Equal(t, expected, mask)
}

func TestRecordNonce13(t *testing.T) {
	iv := []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab}
	nonce, err := recordNonce13(iv, 0x0102030405060708)
	require.NoError(t, err)

	assert.Equal(t, []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa5, 0xa7, 0xa5, 0xa3, 0xad, 0xaf, 0xad, 0xa3}, nonce)
	assert.Equal(t, []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab}, iv)
}

func TestNewAESGCMRecordProtection13RejectsInvalidAESKeyLength(t *testing.T) {
	suite := NewTLSAes256GcmSha384()
	_, err := newAESGCMRecordProtection13(
		suite.HashFunc(),
		trafficSecret13(suite, 0x5a),
		trafficSecret13(suite, 0x6a),
		31,
	)
	assert.Error(t, err)
}

func TestDeriveRecordTrafficKeys13RejectsInvalidKeyLength(t *testing.T) {
	suite := NewTLSAes256GcmSha384()
	_, err := deriveRecordTrafficKeys13(suite.HashFunc(), trafficSecret13(suite, 0x3c), 0)
	assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)
}
