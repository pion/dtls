package ciphersuite

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"golang.org/x/crypto/chacha20poly1305"
)

type ChaCha struct {
	localCipher  cipher.AEAD
	remoteCipher cipher.AEAD

	localWriteIV  []byte
	remoteWriteIV []byte
}

func NewChaCha(localKey, localIV, remoteKey, remoteIV []byte) (*ChaCha, error) {
	c := &ChaCha{
		localWriteIV:  localIV,
		remoteWriteIV: remoteIV,
	}

	var err error
	c.localCipher, err = chacha20poly1305.New(localKey)
	if err != nil {
		return nil, fmt.Errorf("create local cipher: %w", err)
	}
	c.remoteCipher, err = chacha20poly1305.New(remoteKey)
	if err != nil {
		return nil, fmt.Errorf("create remote cipher: %w", err)
	}
	return c, nil
}

// Encrypt encrypts a DTLS RecordLayer message using ChaCha20-Poly1305
func (c *ChaCha) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	payload := raw[pkt.Header.Size():]
	raw = raw[:pkt.Header.Size()]

	// Nonce = 4B 固定IV + 8B 显式随机
	nonce := append(append([]byte{}, c.localWriteIV[:4]...), make([]byte, 8)...)
	if _, err := rand.Read(nonce[4:]); err != nil {
		return nil, err
	}

	// AdditionalData = record header + length
	var additionalData []byte
	if pkt.Header.ContentType == protocol.ContentTypeConnectionID {
		additionalData = generateAEADAdditionalDataCID(&pkt.Header, len(payload))
	} else {
		additionalData = generateAEADAdditionalData(&pkt.Header, len(payload))
	}

	encryptedPayload := c.localCipher.Seal(nil, nonce, payload, additionalData)

	// 把显式 8B Nonce + ciphertext 写回 raw
	encryptedPayload = append(nonce[4:], encryptedPayload...)
	raw = append(raw, encryptedPayload...)

	// 更新 record size (包含 explicit nonce + tag)
	binary.BigEndian.PutUint16(raw[pkt.Header.Size()-2:], uint16(len(raw)-pkt.Header.Size()))

	return raw, nil
}

// Decrypt decrypts a DTLS RecordLayer message using ChaCha20-Poly1305
func (c *ChaCha) Decrypt(header recordlayer.Header, in []byte) ([]byte, error) {
	if err := header.Unmarshal(in); err != nil {
		return nil, err
	}
	switch {
	case header.ContentType == protocol.ContentTypeChangeCipherSpec:
		return in, nil
	case len(in) <= (8 + header.Size()):
		return nil, fmt.Errorf("not enough room for nonce")
	}

	// Nonce = 4B 固定IV + 8B 显式
	nonce := append(append([]byte{}, c.remoteWriteIV[:4]...), in[header.Size():header.Size()+8]...)
	out := in[header.Size()+8:]

	// AdditionalData
	var additionalData []byte
	if header.ContentType == protocol.ContentTypeConnectionID {
		additionalData = generateAEADAdditionalDataCID(&header, len(out)-chacha20poly1305.Overhead)
	} else {
		additionalData = generateAEADAdditionalData(&header, len(out)-chacha20poly1305.Overhead)
	}

	// Decrypt
	plain, err := c.remoteCipher.Open(out[:0], nonce, out, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %v", err)
	}
	return append(in[:header.Size()], plain...), nil
}
