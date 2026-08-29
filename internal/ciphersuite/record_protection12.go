// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"sync"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/ccm"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	dtls12ExplicitNonceLength = 8
	ccmTagLength8             = 8
	ccmTagLength              = 16
	ccmNonceLength            = 12
	chachaTagLength           = 16
	chachaNonceLength         = 12
)

type aeadProtection struct {
	local, remote     cipher.AEAD
	localIV, remoteIV []byte
	tagLength         int
	nonceBufferPool   sync.Pool
}

func newAEADProtection(
	local cipher.AEAD,
	localIV []byte,
	remote cipher.AEAD,
	remoteIV []byte,
) (*aeadProtection, error) {
	if local == nil || remote == nil {
		return nil, dtlserrors.ErrLengthMismatch
	}
	nonceLength := local.NonceSize()
	implicitIVLength := nonceLength - dtls12ExplicitNonceLength
	if implicitIVLength <= 0 || remote.NonceSize() != nonceLength ||
		local.Overhead() != remote.Overhead() || len(localIV) != implicitIVLength || len(remoteIV) != implicitIVLength {
		return nil, dtlserrors.ErrLengthMismatch
	}

	return &aeadProtection{
		local:     local,
		remote:    remote,
		localIV:   bytes.Clone(localIV),
		remoteIV:  bytes.Clone(remoteIV),
		tagLength: local.Overhead(),
		nonceBufferPool: sync.Pool{New: func() any {
			nonce := make([]byte, nonceLength)

			return &nonce
		}},
	}, nil
}

func (a *aeadProtection) Seal(record cryptosuite.Record, plaintext []byte) ([]byte, error) {
	additionalData, err := record.AuthenticationData(len(plaintext))
	if err != nil {
		return nil, err
	}

	noncePtr := a.nonceBufferPool.Get().(*[]byte) //nolint:forcetypeassert
	nonce := *noncePtr
	defer a.nonceBufferPool.Put(noncePtr)

	copy(nonce, a.localIV)
	binary.BigEndian.PutUint64(nonce[len(a.localIV):], record.RecordNumber())

	protected := make([]byte, dtls12ExplicitNonceLength, dtls12ExplicitNonceLength+len(plaintext)+a.tagLength)
	copy(protected, nonce[len(a.localIV):])

	return a.local.Seal(protected, nonce, plaintext, additionalData), nil
}

func (a *aeadProtection) Open(record cryptosuite.Record, protected []byte) ([]byte, error) {
	if len(protected) < dtls12ExplicitNonceLength+a.tagLength {
		return nil, cryptosuite.ErrAuthenticationFailed
	}
	plaintextLen := len(protected) - dtls12ExplicitNonceLength - a.tagLength
	additionalData, err := record.AuthenticationData(plaintextLen)
	if err != nil {
		return nil, cryptosuite.ErrAuthenticationFailed
	}

	noncePtr := a.nonceBufferPool.Get().(*[]byte) //nolint:forcetypeassert
	nonce := *noncePtr
	defer a.nonceBufferPool.Put(noncePtr)

	copy(nonce, a.remoteIV)
	copy(nonce[len(a.remoteIV):], protected[:dtls12ExplicitNonceLength])
	plaintext, err := a.remote.Open(nil, nonce, protected[dtls12ExplicitNonceLength:], additionalData)
	if err != nil {
		return nil, cryptosuite.ErrAuthenticationFailed
	}

	return plaintext, nil
}

type blockAEADFactory func(cipher.Block) (cipher.AEAD, error)

func newAESAEADProtection(
	factory blockAEADFactory,
	localKey, localIV, remoteKey, remoteIV []byte,
) (cryptosuite.Protection, error) {
	localBlock, err := aes.NewCipher(bytes.Clone(localKey))
	if err != nil {
		return nil, err
	}
	local, err := factory(localBlock)
	if err != nil {
		return nil, err
	}

	remoteBlock, err := aes.NewCipher(bytes.Clone(remoteKey))
	if err != nil {
		return nil, err
	}
	remote, err := factory(remoteBlock)
	if err != nil {
		return nil, err
	}

	return newAEADProtection(local, localIV, remote, remoteIV)
}

func newCCM(tagLength int, localKey, localIV, remoteKey, remoteIV []byte) (cryptosuite.Protection, error) {
	return newAESAEADProtection(
		func(block cipher.Block) (cipher.AEAD, error) {
			return ccm.NewCCM(block, tagLength, ccmNonceLength)
		},
		localKey, localIV, remoteKey, remoteIV,
	)
}

func newGCM(localKey, localIV, remoteKey, remoteIV []byte) (cryptosuite.Protection, error) {
	return newAESAEADProtection(cipher.NewGCM, localKey, localIV, remoteKey, remoteIV)
}

type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

type cbcProtection struct {
	writeCBC, readCBC cbcMode
	writeMAC, readMAC []byte
	hashFunc          prf.HashFunc
}

func newCBC(
	localKey, localIV, localMAC, remoteKey, remoteIV, remoteMAC []byte,
	hashFunc prf.HashFunc,
) (cryptosuite.Protection, error) {
	if hashFunc == nil || hashFunc() == nil {
		return nil, dtlserrors.ErrInvalidHashAlgorithm
	}

	writeBlock, err := aes.NewCipher(bytes.Clone(localKey))
	if err != nil {
		return nil, err
	}
	readBlock, err := aes.NewCipher(bytes.Clone(remoteKey))
	if err != nil {
		return nil, err
	}
	if len(localIV) != writeBlock.BlockSize() || len(remoteIV) != readBlock.BlockSize() {
		return nil, dtlserrors.ErrLengthMismatch
	}

	writeCBC, ok := cipher.NewCBCEncrypter(writeBlock, bytes.Clone(localIV)).(cbcMode)
	if !ok {
		return nil, dtlserrors.ErrFailedToCast
	}
	readCBC, ok := cipher.NewCBCDecrypter(readBlock, bytes.Clone(remoteIV)).(cbcMode)
	if !ok {
		return nil, dtlserrors.ErrFailedToCast
	}

	return &cbcProtection{
		writeCBC: writeCBC,
		readCBC:  readCBC,
		writeMAC: bytes.Clone(localMAC),
		readMAC:  bytes.Clone(remoteMAC),
		hashFunc: hashFunc,
	}, nil
}

func (c *cbcProtection) Seal(record cryptosuite.Record, plaintext []byte) ([]byte, error) {
	blockSize := c.writeCBC.BlockSize()
	payload := make([]byte, len(plaintext), len(plaintext)+c.hashFunc().Size()+blockSize)
	copy(payload, plaintext)

	mac, err := recordMAC(record, payload, nil, c.writeMAC, c.hashFunc)
	if err != nil {
		return nil, err
	}
	payload = append(payload, mac...)

	padding := make([]byte, blockSize-len(payload)%blockSize)
	for i := range padding {
		padding[i] = byte(len(padding) - 1) //nolint:gosec
	}
	payload = append(payload, padding...)

	iv := make([]byte, blockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	c.writeCBC.SetIV(iv)
	c.writeCBC.CryptBlocks(payload, payload)

	protected := make([]byte, len(iv)+len(payload))
	copy(protected, iv)
	copy(protected[len(iv):], payload)

	return protected, nil
}

func (c *cbcProtection) Open(record cryptosuite.Record, protected []byte) ([]byte, error) {
	blockSize := c.readCBC.BlockSize()
	mac := c.hashFunc()
	if len(protected)%blockSize != 0 || len(protected) < blockSize+max(mac.Size()+1, blockSize) {
		return nil, cryptosuite.ErrAuthenticationFailed
	}

	c.readCBC.SetIV(protected[:blockSize])
	body := bytes.Clone(protected[blockSize:])
	c.readCBC.CryptBlocks(body, body)

	paddingLen, paddingGood := examinePadding(body)
	macSize := mac.Size()
	macSpaceGood := subtle.ConstantTimeLessOrEq(paddingLen, len(body)-macSize)
	paddingAndSpaceGood := int(paddingGood&1) & macSpaceGood
	paddingLen = subtle.ConstantTimeSelect(paddingAndSpaceGood, paddingLen, 1)

	dataEnd := len(body) - macSize - paddingLen
	expectedMAC := body[dataEnd : dataEnd+macSize]
	actualMAC, err := recordMAC(
		record, body[:dataEnd], body[dataEnd+macSize:], c.readMAC, c.hashFunc,
	)
	macGood := subtle.ConstantTimeCompare(actualMAC, expectedMAC)
	macAndPaddingGood := macGood & paddingAndSpaceGood
	if err != nil || macAndPaddingGood != 1 {
		return nil, cryptosuite.ErrAuthenticationFailed
	}

	return body[:dataEnd], nil
}

func recordMAC(
	record cryptosuite.Record,
	payload, extra, key []byte,
	hashFunc prf.HashFunc,
) ([]byte, error) {
	additionalData, err := record.AuthenticationData(len(payload))
	if err != nil {
		return nil, err
	}
	mac := hmac.New(hashFunc, key)
	if _, err = mac.Write(additionalData); err != nil {
		return nil, err
	}
	if _, err = mac.Write(payload); err != nil {
		return nil, err
	}
	digest := mac.Sum(nil)
	if len(extra) != 0 {
		if _, err = mac.Write(extra); err != nil {
			return nil, err
		}
	}

	return digest, nil
}

type chaCha20Poly1305Protection struct {
	local, remote     cipher.AEAD
	localIV, remoteIV []byte
}

func newChaCha20Poly1305(
	localKey, localIV, remoteKey, remoteIV []byte,
) (cryptosuite.Protection, error) {
	if len(localIV) != chachaNonceLength || len(remoteIV) != chachaNonceLength {
		return nil, dtlserrors.ErrLengthMismatch
	}
	local, err := chacha20poly1305.New(bytes.Clone(localKey))
	if err != nil {
		return nil, err
	}
	remote, err := chacha20poly1305.New(bytes.Clone(remoteKey))
	if err != nil {
		return nil, err
	}

	return &chaCha20Poly1305Protection{
		local: local, remote: remote,
		localIV: bytes.Clone(localIV), remoteIV: bytes.Clone(remoteIV),
	}, nil
}

func (c *chaCha20Poly1305Protection) Seal(
	record cryptosuite.Record,
	plaintext []byte,
) ([]byte, error) {
	additionalData, err := record.AuthenticationData(len(plaintext))
	if err != nil {
		return nil, err
	}
	nonce := xorNonce(c.localIV, record.RecordNumber())

	return c.local.Seal(nil, nonce[:], plaintext, additionalData), nil
}

func (c *chaCha20Poly1305Protection) Open(
	record cryptosuite.Record,
	protected []byte,
) ([]byte, error) {
	if len(protected) < chachaTagLength {
		return nil, cryptosuite.ErrAuthenticationFailed
	}
	additionalData, err := record.AuthenticationData(len(protected) - chachaTagLength)
	if err != nil {
		return nil, cryptosuite.ErrAuthenticationFailed
	}
	nonce := xorNonce(c.remoteIV, record.RecordNumber())
	plaintext, err := c.remote.Open(nil, nonce[:], protected, additionalData)
	if err != nil {
		return nil, cryptosuite.ErrAuthenticationFailed
	}

	return plaintext, nil
}

func xorNonce(iv []byte, recordNumber uint64) [chachaNonceLength]byte {
	var nonce [chachaNonceLength]byte
	copy(nonce[:], iv)
	for i := range 8 {
		nonce[4+i] ^= byte(recordNumber >> (56 - uint(i)*8)) //nolint:gosec // Intentional truncation.
	}

	return nonce
}

// examinePadding returns the length of valid TLS padding
// and 255 for valid padding or zero otherwise (in constant time).
func examinePadding(payload []byte) (toRemove int, good byte) {
	if len(payload) == 0 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen) //nolint:gosec
	good = byte(int32(^t) >> 31)                 //nolint:gosec

	for i := range min(256, len(payload)) {
		t = uint(paddingLen) - uint(i)
		mask := byte(int32(^t) >> 31) //nolint:gosec
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7) //nolint:gosec
	paddingLen &= good

	return int(paddingLen) + 1, good
}
