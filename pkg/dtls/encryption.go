package dtls

import (
	"crypto/aes"
	"crypto/cipher"
)

const aesGCMTagLength = 16

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}
