package ciphersuite

import (
	"crypto/rand"
	"fmt"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeySize is the size of the key used by this AEAD, in bytes.
	KeySize = 32

	// NonceSize is the size of the nonce used with the standard variant of this
	// AEAD, in bytes.
	//
	// Note that this is too short to be safely generated at random if the same
	// key is reused more than 2³² times.
	NonceSize = 12

	// NonceSizeX is the size of the nonce used with the XChaCha20-Poly1305
	// variant of this AEAD, in bytes.
	NonceSizeX = 24

	// Overhead is the size of the Poly1305 authentication tag, and the
	// difference between a ciphertext length and its plaintext.
	Overhead = 16
)

func TestChaCha(t *testing.T) {
	// key should be randomly generated or derived from a function like Argon2.
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	// Encryption.
	var encryptedMsg []byte
	{
		msg := []byte("Gophers, gophers, gophers everywhere!")

		// Select a random nonce, and leave capacity for the ciphertext.
		nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())
		if _, err := rand.Read(nonce); err != nil {
			panic(err)
		}

		// Encrypt the message and append the ciphertext to the nonce.
		encryptedMsg = aead.Seal(nonce, nonce, msg, nil)
	}

	// Decryption.
	{
		if len(encryptedMsg) < aead.NonceSize() {
			panic("ciphertext too short")
		}

		// Split nonce and ciphertext.
		nonce, ciphertext := encryptedMsg[:aead.NonceSize()], encryptedMsg[aead.NonceSize():]

		// Decrypt the message and check it wasn't tampered with.
		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			panic(err)
		}

		fmt.Printf("%s\n", plaintext)
	}
}
