package ciphersuite

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func TestChaChaEncryptDecrypt(t *testing.T) {
	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)
	if _, err := rand.Read(masterSecret); err != nil {
		t.Fatalf("rand read masterSecret: %v", err)
	}
	if _, err := rand.Read(clientRandom); err != nil {
		t.Fatalf("rand read clientRandom: %v", err)
	}
	if _, err := rand.Read(serverRandom); err != nil {
		t.Fatalf("rand read serverRandom: %v", err)
	}

	// 初始化 client-side cipher (isClient = true)
	csClient := &TLSEcdheRsaWithChaCha20Poly1305Sha256{
	}
	if err := csClient.Init(masterSecret, clientRandom, serverRandom, true); err != nil {
		t.Fatalf("client Init failed: %v", err)
	}

	// 初始化 server-side cipher (isClient = false)
	csServer := &TLSEcdheRsaWithChaCha20Poly1305Sha256{
	}
	if err := csServer.Init(masterSecret, clientRandom, serverRandom, false); err != nil {
		t.Fatalf("server Init failed: %v", err)
	}

	rl := &recordlayer.RecordLayer{
		Header: recordlayer.Header{
			ContentType:    protocol.ContentTypeApplicationData,
			Version:        protocol.Version1_2,
			Epoch:          1,
			SequenceNumber: 1,
		},
	}

	plaintext := []byte("hello chacha20-poly1305 in pion/dtls!")


	hb, err := rl.Header.Marshal()
	if err != nil {
		t.Fatalf("Header.Marshal failed: %v", err)
	}
	raw := make([]byte, len(hb)+len(plaintext))
	copy(raw[:len(hb)], hb)
	copy(raw[len(hb):], plaintext)

	// client 加密
	encrypted, err := csClient.Encrypt(rl, raw)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// server 解密 —— 传入一个零值 header，Decrypt 会先从输入解析 header（header.Unmarshal）
	decrypted, err := csServer.Decrypt(recordlayer.Header{}, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// 解密后的 payload 在 header bytes 之后
	got := decrypted[len(hb):]
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch\ngot:  %x\nwant: %x", got, plaintext)
	}

	fmt.Println("decrypted:", string(got))
}
