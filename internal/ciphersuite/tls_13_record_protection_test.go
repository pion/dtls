// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"bytes"
	"crypto/aes"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type aesGCMRecordProtection13TestCase struct {
	name   string
	suite  tls13RecordProtectionSuite
	keyLen int
}

type tls13RecordProtectionSuite interface {
	CipherSuite
	newRecordProtection(localTrafficSecret, remoteTrafficSecret []byte) (*recordProtection13, error)
}

func aesGCMRecordProtection13TestCases() []aesGCMRecordProtection13TestCase {
	return []aesGCMRecordProtection13TestCase{
		{
			name:   "TLS_AES_128_GCM_SHA256",
			suite:  NewTLSAes128GcmSha256(),
			keyLen: tls13AES128GCMKeyLen,
		},
		{
			name:   "TLS_AES_256_GCM_SHA384",
			suite:  NewTLSAes256GcmSha384(),
			keyLen: tls13AES256GCMKeyLen,
		},
	}
}

func trafficSecret13(suite tls13RecordProtectionSuite, fill byte) []byte {
	hashFunc := suite.HashFunc()

	return bytes.Repeat([]byte{fill}, hashFunc().Size())
}

func TestDeriveRecordTrafficKeys13AESGCMSuites(t *testing.T) {
	for _, testCase := range aesGCMRecordProtection13TestCases() {
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

func TestTLS13CipherSuiteNewRecordProtectionAESGCMSuites(t *testing.T) {
	for _, testCase := range aesGCMRecordProtection13TestCases() {
		t.Run(testCase.name, func(t *testing.T) {
			localTrafficSecret := trafficSecret13(testCase.suite, 0x5a)
			remoteTrafficSecret := trafficSecret13(testCase.suite, 0x6b)

			protection, err := testCase.suite.newRecordProtection(localTrafficSecret, remoteTrafficSecret)
			require.NoError(t, err)
			require.NotNil(t, protection.local.aead)
			require.NotNil(t, protection.remote.aead)

			assert.Equal(t, tls13AEADWriteIVLen, protection.local.aead.NonceSize())
			assert.Equal(t, tls13AESGCMTagLen, protection.local.aead.Overhead())
			require.Len(t, protection.local.iv, tls13AEADWriteIVLen)
			require.Len(t, protection.remote.iv, tls13AEADWriteIVLen)
			require.Len(t, protection.local.sequenceNumberKey, testCase.keyLen)
			require.Len(t, protection.remote.sequenceNumberKey, testCase.keyLen)
			assert.NotEqual(t, protection.local.iv, protection.remote.iv)
			assert.NotEqual(t, protection.local.sequenceNumberKey, protection.remote.sequenceNumberKey)

			plaintext := []byte("dtls13 aes-gcm")
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

func TestTLS13CipherSuiteNewRecordProtectionRejectsChaCha20Poly1305(t *testing.T) {
	suite := NewTLSChacha20Poly1305Sha256()

	_, err := suite.newRecordProtection(trafficSecret13(suite, 0x5a), trafficSecret13(suite, 0x6b))
	assert.ErrorIs(t, err, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented)
}

func TestRecordProtection13SealOpenSyntheticTrafficSecret(t *testing.T) {
	for _, testCase := range aesGCMRecordProtection13TestCases() {
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
			require.Len(t, record.EncryptedRecord, len(plaintext)+1+tls13AESGCMTagLen)

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
	for _, testCase := range aesGCMRecordProtection13TestCases() {
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
	for _, testCase := range aesGCMRecordProtection13TestCases() {
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
	for _, testCase := range aesGCMRecordProtection13TestCases() {
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
			require.Len(t, mask, aes.BlockSize)

			block, err := aes.NewCipher(protection.local.sequenceNumberKey)
			require.NoError(t, err)
			expectedMask := make([]byte, aes.BlockSize)
			block.Encrypt(expectedMask, record.EncryptedRecord[:aes.BlockSize])
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
	suite := NewTLSAes128GcmSha256()
	protection, err := suite.newRecordProtection(trafficSecret13(suite, 0xd9), trafficSecret13(suite, 0xda))
	require.NoError(t, err)

	_, err = protection.sequenceNumberMask(bytes.Repeat([]byte{0x01}, aes.BlockSize-1))
	assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)
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
