// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
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

	maxDTLSPlaintextRecordLen13  = 1 << 14
	maxDTLSCiphertextRecordLen13 = maxDTLSPlaintextRecordLen13 + 256
)

type recordSequenceNumberMaskFunc13 func(sequenceNumberKey, encryptedRecord []byte) ([]byte, error)

type recordTrafficKeys13 struct {
	key               []byte
	iv                []byte
	sequenceNumberKey []byte
}

type recordTrafficProtection13 struct {
	aead               cipher.AEAD
	iv                 []byte
	sequenceNumberKey  []byte
	sequenceNumberMask recordSequenceNumberMaskFunc13
}

type recordProtection13 struct {
	local  recordTrafficProtection13
	remote recordTrafficProtection13
}

func newAES128GCMRecordProtection13(
	hashFunc func() hash.Hash,
	localTrafficSecret, remoteTrafficSecret []byte,
) (*recordProtection13, error) {
	return newAESGCMRecordProtection13(hashFunc, localTrafficSecret, remoteTrafficSecret, tls13AES128GCMKeyLen)
}

func newAES256GCMRecordProtection13(
	hashFunc func() hash.Hash,
	localTrafficSecret, remoteTrafficSecret []byte,
) (*recordProtection13, error) {
	return newAESGCMRecordProtection13(hashFunc, localTrafficSecret, remoteTrafficSecret, tls13AES256GCMKeyLen)
}

func newAESGCMRecordProtection13(
	hashFunc func() hash.Hash,
	localTrafficSecret, remoteTrafficSecret []byte,
	keyLen int,
) (*recordProtection13, error) {
	local, err := newAESGCMRecordTrafficProtection13(hashFunc, localTrafficSecret, keyLen)
	if err != nil {
		return nil, err
	}

	remote, err := newAESGCMRecordTrafficProtection13(hashFunc, remoteTrafficSecret, keyLen)
	if err != nil {
		return nil, err
	}

	return &recordProtection13{
		local:  local,
		remote: remote,
	}, nil
}

func newAESGCMRecordTrafficProtection13(
	hashFunc func() hash.Hash,
	trafficSecret []byte,
	keyLen int,
) (recordTrafficProtection13, error) {
	keys, err := deriveRecordTrafficKeys13(hashFunc, trafficSecret, keyLen)
	if err != nil {
		return recordTrafficProtection13{}, err
	}

	block, err := aes.NewCipher(keys.key)
	if err != nil {
		return recordTrafficProtection13{}, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return recordTrafficProtection13{}, err
	}

	return recordTrafficProtection13{
		aead:               aead,
		iv:                 keys.iv,
		sequenceNumberKey:  keys.sequenceNumberKey,
		sequenceNumberMask: recordSequenceNumberMaskAES13,
	}, nil
}

func newChaCha20Poly1305RecordProtection13(
	hashFunc func() hash.Hash,
	localTrafficSecret, remoteTrafficSecret []byte,
) (*recordProtection13, error) {
	local, err := newChaCha20Poly1305RecordTrafficProtection13(hashFunc, localTrafficSecret)
	if err != nil {
		return nil, err
	}

	remote, err := newChaCha20Poly1305RecordTrafficProtection13(hashFunc, remoteTrafficSecret)
	if err != nil {
		return nil, err
	}

	return &recordProtection13{
		local:  local,
		remote: remote,
	}, nil
}

func newChaCha20Poly1305RecordTrafficProtection13(
	hashFunc func() hash.Hash,
	trafficSecret []byte,
) (recordTrafficProtection13, error) {
	keys, err := deriveRecordTrafficKeys13(hashFunc, trafficSecret, tls13ChaCha20Poly1305KeyLen)
	if err != nil {
		return recordTrafficProtection13{}, err
	}

	aead, err := chacha20poly1305.New(keys.key)
	if err != nil {
		return recordTrafficProtection13{}, err
	}

	return recordTrafficProtection13{
		aead:               aead,
		iv:                 keys.iv,
		sequenceNumberKey:  keys.sequenceNumberKey,
		sequenceNumberMask: recordSequenceNumberMaskChaCha20Poly1305TLS13,
	}, nil
}

func (r *recordProtection13) seal(
	header recordlayer.UnifiedHeader,
	sequenceNumber uint64,
	contentType protocol.ContentType,
	plaintext []byte,
) (recordlayer.CiphertextRecord13, error) {
	if len(plaintext) > maxDTLSPlaintextRecordLen13 {
		return recordlayer.CiphertextRecord13{}, dtlserrors.ErrInvalidPacketLength
	}

	innerPlaintext, err := (&recordlayer.InnerPlaintext{
		Content:  plaintext,
		RealType: contentType,
	}).Marshal()
	if err != nil {
		return recordlayer.CiphertextRecord13{}, err
	}

	ciphertextLen := len(innerPlaintext) + r.local.aead.Overhead()
	if ciphertextLen > maxDTLSCiphertextRecordLen13 {
		return recordlayer.CiphertextRecord13{}, dtlserrors.ErrInvalidPacketLength
	}

	header.SeqBit = true
	header.Length = uint16(ciphertextLen) //nolint:gosec // G115: checked above.
	header.LengthBit = true
	additionalData, err := header.Marshal()
	if err != nil {
		return recordlayer.CiphertextRecord13{}, err
	}

	nonce, err := recordNonce13(r.local.iv, sequenceNumber)
	if err != nil {
		return recordlayer.CiphertextRecord13{}, err
	}

	// Sequence-number masking is kept separate until DTLS 1.3 record writer integration.
	return recordlayer.CiphertextRecord13{
		Header:          header,
		EncryptedRecord: r.local.aead.Seal(nil, nonce, innerPlaintext, additionalData),
	}, nil
}

func (r *recordProtection13) open(
	header recordlayer.UnifiedHeader,
	sequenceNumber uint64,
	encryptedRecord []byte,
) (recordlayer.InnerPlaintext, error) {
	additionalData, err := header.Marshal()
	if err != nil {
		return recordlayer.InnerPlaintext{}, err
	}

	nonce, err := recordNonce13(r.remote.iv, sequenceNumber)
	if err != nil {
		return recordlayer.InnerPlaintext{}, err
	}

	innerPlaintextRaw, err := r.remote.aead.Open(nil, nonce, encryptedRecord, additionalData)
	if err != nil {
		return recordlayer.InnerPlaintext{}, fmt.Errorf("%w: %v", dtlserrors.ErrDecryptPacket, err) //nolint:errorlint
	}

	var innerPlaintext recordlayer.InnerPlaintext
	if err = innerPlaintext.Unmarshal(innerPlaintextRaw); err != nil {
		return recordlayer.InnerPlaintext{}, err
	}

	return innerPlaintext, nil
}

func (r *recordProtection13) sequenceNumberMask(encryptedRecord []byte) ([]byte, error) {
	return r.local.sequenceNumberMask13(encryptedRecord)
}

func (r *recordProtection13) maskLocalSequenceNumber13(
	header *recordlayer.UnifiedHeader,
	encryptedRecord []byte,
) error {
	mask, err := r.local.sequenceNumberMask13(encryptedRecord)
	if err != nil {
		return err
	}

	return applySequenceNumberMask13(header, mask)
}

func (r *recordProtection13) unmaskRemoteSequenceNumber13(
	header *recordlayer.UnifiedHeader,
	encryptedRecord []byte,
) error {
	mask, err := r.remote.sequenceNumberMask13(encryptedRecord)
	if err != nil {
		return err
	}

	return applySequenceNumberMask13(header, mask)
}

func (p recordTrafficProtection13) sequenceNumberMask13(encryptedRecord []byte) ([]byte, error) {
	if p.sequenceNumberMask == nil {
		return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	return p.sequenceNumberMask(p.sequenceNumberKey, encryptedRecord)
}

func applySequenceNumberMask13(header *recordlayer.UnifiedHeader, mask []byte) error {
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

	if len(mask) < 1 {
		return dtlserrors.ErrBufferTooSmall
	}

	header.SequenceNumber = (header.SequenceNumber ^ uint16(mask[0])) & 0x00ff

	return nil
}

func validateSequenceNumberLowBits13(header recordlayer.UnifiedHeader, sequenceNumber uint64) error {
	if header.SeqBit {
		if uint64(header.SequenceNumber) != sequenceNumber&0xffff {
			return dtlserrors.ErrInvalidCiphertextHeader
		}

		return nil
	}

	if uint64(header.SequenceNumber)&0xff != sequenceNumber&0xff {
		return dtlserrors.ErrInvalidCiphertextHeader
	}

	return nil
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

	nonce := append([]byte(nil), iv...)
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
