// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tls13RecordProtectionSuite = cryptosuite.TrafficSuite

func testSuite13(id cryptosuite.ID) tls13RecordProtectionSuite {
	return ForID(id).(tls13RecordProtectionSuite) //nolint:forcetypeassert // test registry is fixed.
}

type recordProtectionPair13 struct {
	local  *recordTrafficProtection13
	remote *recordTrafficProtection13
}

func (r *recordProtectionPair13) seal(header recordlayer.UnifiedHeader, sequenceNumber uint64, plaintext []byte) (recordlayer.CiphertextRecord, error) {
	innerPlaintext, err := (&recordlayer.InnerPlaintext{Content: plaintext, RealType: protocol.ContentTypeApplicationData}).Marshal()
	if err != nil {
		return recordlayer.CiphertextRecord{}, err
	}

	header.SequenceNumber = uint16(sequenceNumber) //nolint:gosec
	header.SeqBit = true
	header.LengthBit = true
	header.Length = uint16(len(innerPlaintext) + r.local.aead.Overhead()) //nolint:gosec
	metadata, err := newUnifiedRecordForTest(header, sequenceNumber, int(header.Length))
	if err != nil {
		return recordlayer.CiphertextRecord{}, err
	}

	protected, err := r.local.Seal(metadata, innerPlaintext)
	if err != nil {
		return recordlayer.CiphertextRecord{}, err
	}

	return recordlayer.CiphertextRecord{Header: header, EncryptedRecord: protected}, nil
}

func (r *recordProtectionPair13) open(header recordlayer.UnifiedHeader, sequenceNumber uint64, encryptedRecord []byte) (recordlayer.InnerPlaintext, error) {
	protectedLen := len(encryptedRecord)
	if header.LengthBit {
		protectedLen = int(header.Length)
	}
	metadata, err := newUnifiedRecordForTest(header, sequenceNumber, protectedLen)
	if err != nil {
		return recordlayer.InnerPlaintext{}, fmt.Errorf("%w: %w", dtlserrors.ErrInvalidCiphertextHeader, err)
	}

	plaintext, err := r.remote.Open(metadata, encryptedRecord)
	if errors.Is(err, cryptosuite.ErrAuthenticationFailed) {
		return recordlayer.InnerPlaintext{}, dtlserrors.ErrDecryptPacket
	}
	if err != nil {
		return recordlayer.InnerPlaintext{}, err
	}

	var innerPlaintext recordlayer.InnerPlaintext
	if err = innerPlaintext.Unmarshal(plaintext); err != nil {
		return recordlayer.InnerPlaintext{}, err
	}

	return innerPlaintext, nil
}

func (r *recordProtectionPair13) sequenceNumberMask(encryptedRecord []byte) ([]byte, error) {
	return r.local.Mask(encryptedRecord)
}

func newUnifiedRecordForTest(header recordlayer.UnifiedHeader, sequenceNumber uint64, protectedLen int) (cryptosuite.Record, error) {
	return NewUnifiedRecord(
		uint64(header.EpochLow),
		sequenceNumber,
		header,
		protectedLen,
	)
}

func applySequenceNumberMask13ForTest(header *recordlayer.UnifiedHeader, mask []byte) error {
	if header == nil {
		return dtlserrors.ErrInvalidCiphertextHeader
	}
	if header.SeqBit {
		if len(mask) < 2 {
			return dtlserrors.ErrBufferTooSmall
		}
		header.SequenceNumber ^= uint16(mask[0])<<8 | uint16(mask[1])

		return nil
	}
	if len(mask) == 0 {
		return dtlserrors.ErrBufferTooSmall
	}
	header.SequenceNumber = (header.SequenceNumber ^ uint16(mask[0])) & 0xff

	return nil
}

func newRecordProtection13ForTest(suite tls13RecordProtectionSuite, localTrafficSecret, remoteTrafficSecret []byte) (*recordProtectionPair13, error) {
	localSecret, err := NewTrafficSecret(localTrafficSecret)
	if err != nil {
		return nil, err
	}
	localProtection, err := suite.NewTrafficProtection(localSecret)
	if err != nil {
		return nil, err
	}
	remoteSecret, err := NewTrafficSecret(remoteTrafficSecret)
	if err != nil {
		return nil, err
	}
	remoteProtection, err := suite.NewTrafficProtection(remoteSecret)
	if err != nil {
		return nil, err
	}
	local, ok := localProtection.(*recordTrafficProtection13)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected local type %T", dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented, localProtection)
	}
	remote, ok := remoteProtection.(*recordTrafficProtection13)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected remote type %T", dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented, remoteProtection)
	}

	return &recordProtectionPair13{
		local:  local,
		remote: remote,
	}, nil
}

func trafficSecret13(suite tls13RecordProtectionSuite, fill byte) []byte {
	hashFunc := suite.HashFunc()

	return bytes.Repeat([]byte{fill}, hashFunc().Size())
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

	clientSecret = mustDecodeHex13(t, "000102030405060708090a0b0c0d0e0f"+"101112131415161718191a1b1c1d1e1f"+"202122232425262728292a2b2c2d2e2f")
	serverSecret = mustDecodeHex13(t, "303132333435363738393a3b3c3d3e3f"+"404142434445464748494a4b4c4d4e4f"+"505152535455565758595a5b5c5d5e5f")

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
			suite:                        func() tls13RecordProtectionSuite { return testSuite13(cryptosuite.TLS_AES_128_GCM_SHA256) },
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
			expectedEncryptedRecord:      "82bacfceae1035329372dbcbdce0240faf434e68077fb4df25edc71ddd89db18" + "b510ccd2518b77499d7e",
			expectedSequenceNumberMask:   "adc05ac9d6be3e1570d34d94457bdb31",
			expectedMaskedSequenceNumber: 0xabc7,
			expectedMaskedRaw:            "3fcafebabeabc7002a82bacfceae1035329372dbcbdce0240faf434e68077fb4df25edc71ddd89db18" + "b510ccd2518b77499d7e",
		},
		{
			name:                         "TLS_AES_256_GCM_SHA384",
			suite:                        func() tls13RecordProtectionSuite { return testSuite13(cryptosuite.TLS_AES_256_GCM_SHA384) },
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
			expectedEncryptedRecord:      "799936beea392e94f73b56ad19e96f5ff607481e8abf5aa6895414e222eea46" + "b4e2385ac65b6fc516ede",
			expectedSequenceNumberMask:   "cdefbbfbc4863ce5602213c2290c989e",
			expectedMaskedSequenceNumber: 0xcbe8,
			expectedMaskedRaw:            "3fcafebabecbe8002a799936beea392e94f73b56ad19e96f5ff607481e8abf5aa6895414e222eea46" + "b4e2385ac65b6fc516ede",
		},
		{
			name:                         "TLS_CHACHA20_POLY1305_SHA256",
			suite:                        func() tls13RecordProtectionSuite { return testSuite13(cryptosuite.TLS_CHACHA20_POLY1305_SHA256) },
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
			expectedEncryptedRecord:      "69f043b34d3e3b856ce115bab907b93c384fe7d6375a38b00d864a1562eedd91" + "f386a79a681d216cd5ff74d73b419b97",
			expectedSequenceNumberMask:   "2e70bc45d477904ca0053b5321f731eaa5abe10c14ddbefe797decfe78d9c802" + "4d8fce70b14fef48c53d095eb737c95812be77d25a1280c60a68d4a8600680c3",
			expectedMaskedSequenceNumber: 0x2877,
			expectedMaskedRaw:            "3fcafebabe2877003069f043b34d3e3b856ce115bab907b93c384fe7d6375a38b00d864a1562eedd91" + "f386a79a681d216cd5ff74d73b419b97",
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
	assertTLS13TrafficKeys(t, clientKeys, vector.expectedClientKey, vector.expectedClientIV, vector.expectedClientSequenceNumber)

	serverKeys, err := deriveRecordTrafficKeys13(suite.HashFunc(), serverSecret, vector.keyLen)
	require.NoError(t, err)
	assertTLS13TrafficKeys(t, serverKeys, vector.expectedServerKey, vector.expectedServerIV, vector.expectedServerSequenceNumber)

	protection, err := newRecordProtection13ForTest(suite, clientSecret, serverSecret)
	require.NoError(t, err)
	peerProtection, err := newRecordProtection13ForTest(suite, serverSecret, clientSecret)
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

	mask, err := protection.local.Mask(record.EncryptedRecord)
	require.NoError(t, err)
	assert.Equal(t, mustDecodeHex13(t, vector.expectedSequenceNumberMask), mask)

	maskedHeader := record.Header
	require.NoError(t, applySequenceNumberMask13ForTest(&maskedHeader, mask))
	assert.Equal(t, vector.expectedMaskedSequenceNumber, maskedHeader.SequenceNumber)

	maskedRaw, err := (&recordlayer.CiphertextRecord{Header: maskedHeader, EncryptedRecord: record.EncryptedRecord}).Marshal()
	require.NoError(t, err)
	assert.Equal(t, mustDecodeHex13(t, vector.expectedMaskedRaw), maskedRaw)

	innerPlaintext, err := peerProtection.open(record.Header, sequenceNumber, record.EncryptedRecord)
	require.NoError(t, err)
	assert.Equal(t, plaintext, innerPlaintext.Content)
	assert.Equal(t, protocol.ContentTypeApplicationData, innerPlaintext.RealType)
	assert.Equal(t, uint(0), innerPlaintext.Zeros)
}

func assertTLS13TrafficKeys(t *testing.T, keys recordTrafficKeys13, expectedKey, expectedIV, expectedSequenceNumberKey string) {
	t.Helper()

	assert.Equal(t, mustDecodeHex13(t, expectedKey), keys.key)
	assert.Equal(t, mustDecodeHex13(t, expectedIV), keys.iv)
	assert.Equal(t, mustDecodeHex13(t, expectedSequenceNumberKey), keys.sequenceNumberKey)
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

	protection, err := newRecordProtection13ForTest(suite, clientSecret, serverSecret)
	require.NoError(t, err)
	peerProtection, err := newRecordProtection13ForTest(suite, serverSecret, clientSecret)
	require.NoError(t, err)

	record, err := protection.seal(
		recordlayer.UnifiedHeader{
			ConnectionID:   []byte{0xca, 0xfe, 0xba, 0xbe},
			SequenceNumber: uint16(sequenceNumber), //nolint:gosec // G115
			EpochLow:       3,
		},
		sequenceNumber,
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
			assert.ErrorIs(t, err, testCase.expectedError)
		})
	}
}

type tls13KnownVectorMutationCase struct {
	name            string
	mutateHeader    func(*recordlayer.UnifiedHeader)
	mutateEncrypted func([]byte)
	sequenceNumber  uint64
	expectedError   error
}

func tls13KnownVectorMutationCases(sequenceNumber uint64) []tls13KnownVectorMutationCase {
	return []tls13KnownVectorMutationCase{
		{name: "header length authenticated", mutateHeader: func(header *recordlayer.UnifiedHeader) { header.Length ^= 0x0001 }, sequenceNumber: sequenceNumber, expectedError: dtlserrors.ErrDecryptPacket},
		{name: "connection id authenticated", mutateHeader: func(header *recordlayer.UnifiedHeader) { header.ConnectionID[0] ^= 0x80 }, sequenceNumber: sequenceNumber, expectedError: dtlserrors.ErrDecryptPacket},
		{name: "nonce sequence number authenticated", sequenceNumber: sequenceNumber + 1, expectedError: dtlserrors.ErrInvalidCiphertextHeader},
		{name: "ciphertext authenticated", mutateEncrypted: func(encryptedRecord []byte) { encryptedRecord[0] ^= 0x80 }, sequenceNumber: sequenceNumber, expectedError: dtlserrors.ErrDecryptPacket},
		{name: "tag authenticated", mutateEncrypted: func(encryptedRecord []byte) { encryptedRecord[len(encryptedRecord)-1] ^= 0x01 }, sequenceNumber: sequenceNumber, expectedError: dtlserrors.ErrDecryptPacket},
	}
}

func TestRecordProtection13SealRejectsOversizedInnerPlaintext(t *testing.T) {
	suite := testSuite13(cryptosuite.TLS_AES_128_GCM_SHA256)
	protection, err := newRecordProtection13ForTest(suite, trafficSecret13(suite, 0xaa), trafficSecret13(suite, 0xab))
	require.NoError(t, err)

	header := recordlayer.UnifiedHeader{SequenceNumber: 0x1234, EpochLow: 2}
	maxContentLen := 1 << 14
	_, err = protection.seal(
		header,
		0x0102030405060708,
		bytes.Repeat([]byte{0x01}, maxContentLen),
	)
	require.NoError(t, err)

	_, err = protection.seal(
		header,
		0x0102030405060708,
		bytes.Repeat([]byte{0x01}, maxContentLen+1),
	)
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidPacketLength)
}

func TestRecordProtection13SequenceNumberMaskRejectsShortCiphertext(t *testing.T) {
	for _, vector := range tls13KnownVectors() {
		t.Run(vector.name, func(t *testing.T) {
			suite := vector.suite()
			protection, err := newRecordProtection13ForTest(suite,
				trafficSecret13(suite, 0xd9),
				trafficSecret13(suite, 0xda),
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

	expected, err := hex.DecodeString("10f1e7e4d13b5915500fdd1fa32071c4" + "c7d1f4c733c068030422aa9ac3d46c4e" + "d2826446079faa0914c2d705d98b02a2" + "b5129cd1de164eb9cbd083e8a2503c4e")
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

func TestLegacyCIDAuthenticationData(t *testing.T) {
	cid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	record, err := NewLegacyRecord(protocol.ContentTypeConnectionID, protocol.Version1_2, 2, 277, cid)
	require.NoError(t, err)
	cid[0] = 0xff

	authenticationData, err := record.AuthenticationData(1784)
	require.NoError(t, err)
	expected := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 25, 8, 25, 254, 253, 0, 2, 0, 0, 0, 0, 1, 21, 1, 2, 3, 4, 5, 6, 7, 8, 6, 248}
	assert.Equal(t, expected, authenticationData)
	authenticationData[0] = 0
	authenticationData, err = record.AuthenticationData(1784)
	require.NoError(t, err)
	assert.Equal(t, expected, authenticationData)
}

func TestBuiltinCBCCapabilities(t *testing.T) {
	cbc := ForID(cryptosuite.TLS_PSK_WITH_AES_128_CBC_SHA256).Capabilities()
	require.NoError(t, cbc.ValidatePlaintextLen(16688, 1<<14))
	sha1CBC := ForID(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA).Capabilities()
	require.NoError(t, sha1CBC.ValidatePlaintextLen(16672, 1<<14))
}

func TestNewAESGCMRecordProtection13RejectsInvalidAESKeyLength(t *testing.T) {
	suite := testSuite13(cryptosuite.TLS_AES_256_GCM_SHA384)
	_, err := newAESGCMRecordTrafficProtection13(
		suite.HashFunc(),
		trafficSecret13(suite, 0x5a),
		31,
	)
	assert.Error(t, err)
}

func TestDeriveRecordTrafficKeys13RejectsInvalidKeyLength(t *testing.T) {
	suite := testSuite13(cryptosuite.TLS_AES_256_GCM_SHA384)
	_, err := deriveRecordTrafficKeys13(suite.HashFunc(), trafficSecret13(suite, 0x3c), 0)
	assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)
}
