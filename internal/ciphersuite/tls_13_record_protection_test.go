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

func TestTLS13CipherSuiteInitFromTrafficSecrets13(t *testing.T) {
	for _, testCase := range recordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			clientSuite := testCase.suite
			serverSuite := newRecordProtection13TestSuite(t, testCase.name)

			clientSecret := trafficSecret13(testCase.suite, 0xa6)
			serverSecret := trafficSecret13(testCase.suite, 0xb6)

			require.False(t, clientSuite.IsInitialized())
			require.False(t, serverSuite.IsInitialized())

			require.NoError(t, clientSuite.InitFromTrafficSecrets13(clientSecret, serverSecret, true))
			require.NoError(t, serverSuite.InitFromTrafficSecrets13(clientSecret, serverSecret, false))

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
