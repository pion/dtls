// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"hash"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v3/pkg/protocol"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	trafficKeyLabel13               = "key"
	trafficIVLabel13                = "iv"
	trafficSequenceNumberKeyLabel13 = "sn"

	tls13AEADWriteIVLen  = 12
	tls13AES128GCMKeyLen = 16
	tls13AES256GCMKeyLen = 32
	tls13AESGCMTagLen    = 16

	tls13ChaCha20Poly1305KeyLen = chacha20poly1305.KeySize
	tls13ChaCha20Poly1305TagLen = chacha20poly1305.Overhead
	tls13ChaCha20BlockLen       = 64

	tls13SequenceNumberMaskSampleLen = 16
)

type recordSequenceNumberMaskFunc13 func(sequenceNumberKey, encryptedRecord []byte) ([]byte, error)

type recordTrafficKeys13 struct {
	key               []byte
	iv                []byte
	sequenceNumberKey []byte
}

type recordTrafficProtection13 struct {
	aead                 cipher.AEAD
	iv                   []byte
	sequenceNumberKey    []byte
	sequenceNumberMaskFn recordSequenceNumberMaskFunc13
}

func newAESGCMRecordTrafficProtection13(
	hashFunc func() hash.Hash,
	trafficSecret []byte,
	keyLen int,
) (*recordTrafficProtection13, error) {
	keys, err := deriveRecordTrafficKeys13(hashFunc, trafficSecret, keyLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(keys.key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &recordTrafficProtection13{
		aead:                 aead,
		iv:                   keys.iv,
		sequenceNumberKey:    keys.sequenceNumberKey,
		sequenceNumberMaskFn: recordSequenceNumberMaskAES13,
	}, nil
}

func newChaCha20Poly1305RecordTrafficProtection13(
	hashFunc func() hash.Hash,
	trafficSecret []byte,
) (*recordTrafficProtection13, error) {
	keys, err := deriveRecordTrafficKeys13(hashFunc, trafficSecret, tls13ChaCha20Poly1305KeyLen)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(keys.key)
	if err != nil {
		return nil, err
	}

	return &recordTrafficProtection13{
		aead:                 aead,
		iv:                   keys.iv,
		sequenceNumberKey:    keys.sequenceNumberKey,
		sequenceNumberMaskFn: recordSequenceNumberMaskChaCha20Poly1305TLS13,
	}, nil
}

// Mask generates the record-number mask for a caller-validated ciphertext sample.
func (r *recordTrafficProtection13) Mask(sample []byte) ([]byte, error) {
	if r.sequenceNumberMaskFn == nil {
		return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	return r.sequenceNumberMaskFn(r.sequenceNumberKey, sample)
}

// Seal protects an already-serialized DTLSInnerPlaintext and returns only the
// encrypted record body.
func (r *recordTrafficProtection13) Seal(
	record ciphersuite.Record,
	plaintext []byte,
) ([]byte, error) {
	capabilities := mustAEADCapabilities(
		protocol.Version1_3,
		0,
		r.aead.Overhead(),
		tls13SequenceNumberMaskSampleLen,
	)
	protectedLen, err := capabilities.ProtectedLen(len(plaintext))
	if err != nil {
		return nil, dtlserrors.ErrInvalidPacketLength
	}
	additionalData, err := record.AuthenticationData(protectedLen)
	if err != nil {
		return nil, err
	}
	nonce, err := recordNonce13(r.iv, record.RecordNumber())
	if err != nil {
		return nil, err
	}

	return r.aead.Seal(nil, nonce, plaintext, additionalData), nil
}

// Open authenticates one protected record body.
func (r *recordTrafficProtection13) Open(
	record ciphersuite.Record,
	encryptedRecord []byte,
) ([]byte, error) {
	capabilities := mustAEADCapabilities(
		protocol.Version1_3,
		0,
		r.aead.Overhead(),
		tls13SequenceNumberMaskSampleLen,
	)
	if _, err := capabilities.PlaintextLenUpperBound(len(encryptedRecord)); err != nil {
		return nil, ciphersuite.ErrAuthenticationFailed
	}
	additionalData, err := record.AuthenticationData(len(encryptedRecord))
	if err != nil {
		return nil, ciphersuite.ErrAuthenticationFailed
	}
	nonce, err := recordNonce13(r.iv, record.RecordNumber())
	if err != nil {
		return nil, err
	}

	plaintext, err := r.aead.Open(nil, nonce, encryptedRecord, additionalData)
	if err != nil {
		return nil, ciphersuite.ErrAuthenticationFailed
	}

	return plaintext, nil
}

func recordSequenceNumberMaskAES13(sequenceNumberKey, encryptedRecord []byte) ([]byte, error) {
	if len(encryptedRecord) < tls13SequenceNumberMaskSampleLen {
		return nil, dtlserrors.ErrBufferTooSmall
	}

	block, err := aes.NewCipher(sequenceNumberKey)
	if err != nil {
		return nil, err
	}

	mask := make([]byte, aes.BlockSize)
	block.Encrypt(mask, encryptedRecord[:aes.BlockSize])

	return mask, nil
}

func recordSequenceNumberMaskChaCha20Poly1305TLS13(sequenceNumberKey, encryptedRecord []byte) ([]byte, error) {
	if len(encryptedRecord) < tls13SequenceNumberMaskSampleLen {
		return nil, dtlserrors.ErrBufferTooSmall
	}

	chacha, err := chacha20.NewUnauthenticatedCipher(sequenceNumberKey, encryptedRecord[4:16])
	if err != nil {
		return nil, err
	}

	chacha.SetCounter(binary.LittleEndian.Uint32(encryptedRecord[:4]))
	mask := make([]byte, tls13ChaCha20BlockLen)
	chacha.XORKeyStream(mask, mask)

	return mask, nil
}

func recordNonce13(iv []byte, sequenceNumber uint64) ([]byte, error) {
	if len(iv) != tls13AEADWriteIVLen {
		return nil, dtlserrors.ErrLengthMismatch
	}

	nonce := bytes.Clone(iv)
	var sequenceNumberBytes [8]byte
	binary.BigEndian.PutUint64(sequenceNumberBytes[:], sequenceNumber)
	for i, b := range sequenceNumberBytes {
		nonce[len(nonce)-len(sequenceNumberBytes)+i] ^= b
	}

	return nonce, nil
}

func deriveRecordTrafficKeys13(
	hashFunc func() hash.Hash,
	trafficSecret []byte,
	keyLen int,
) (recordTrafficKeys13, error) {
	if keyLen <= 0 {
		return recordTrafficKeys13{}, dtlserrors.ErrLengthMismatch
	}

	key, err := keyschedule.HkdfExpandLabel(
		hashFunc,
		trafficSecret,
		trafficKeyLabel13,
		nil,
		keyLen,
	)
	if err != nil {
		return recordTrafficKeys13{}, err
	}

	iv, err := keyschedule.HkdfExpandLabel(
		hashFunc,
		trafficSecret,
		trafficIVLabel13,
		nil,
		tls13AEADWriteIVLen,
	)
	if err != nil {
		return recordTrafficKeys13{}, err
	}

	sequenceNumberKey, err := keyschedule.HkdfExpandLabel(
		hashFunc,
		trafficSecret,
		trafficSequenceNumberKeyLabel13,
		nil,
		keyLen,
	)
	if err != nil {
		return recordTrafficKeys13{}, err
	}

	return recordTrafficKeys13{
		key:               key,
		iv:                iv,
		sequenceNumberKey: sequenceNumberKey,
	}, nil
}
