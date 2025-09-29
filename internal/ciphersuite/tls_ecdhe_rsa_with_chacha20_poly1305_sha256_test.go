package ciphersuite

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)



// TestChaChaEncryptDecrypt 验证 ChaCha20-Poly1305 的 Encrypt -> Decrypt 能正确还原明文。
// 注意：raw 必须包含与 pkt.Header 一致的序列化 header bytes（即调用 Header.Marshal() 的结果）。
func TestChaChaEncryptDecrypt(t *testing.T) {
	// 随机材料
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

	// init cipher suite (client side)
	cs := &TLSEcdheRsaWithChaCha20Poly1305Sha256{
		keyLen: 32,
		ivLen:  12,
	}
	if err := cs.Init(masterSecret, clientRandom, serverRandom, true); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// 构造 RecordLayer header（数值可任意，但 Header.Marshal() 后要写入 raw）
	rl := &recordlayer.RecordLayer{
		Header: recordlayer.Header{
			ContentType:    protocol.ContentTypeApplicationData,
			Version:        protocol.Version1_2,
			Epoch:          1,
			SequenceNumber: 1,
		},
	}

	plaintext := []byte("hello chacha20-poly1305 in pion/dtls!")

	// 把 header 序列化并写入 raw 的前部 —— 这是关键
	hb, err := rl.Header.Marshal()
	if err != nil {
		t.Fatalf("Header.Marshal failed: %v", err)
	}
	raw := make([]byte, len(hb)+len(plaintext))
	copy(raw[:len(hb)], hb)
	copy(raw[len(hb):], plaintext)

	// 加密（返回的 encrypted 包含 header bytes + explicit nonce + ciphertext+tag）
	encrypted, err := cs.Encrypt(rl, raw)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 解密（注意 Decrypt 会从 encrypted 中解析 header）
	decrypted, err := cs.Decrypt(rl.Header, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// 解密结果中的 payload 在 header bytes 之后
	got := decrypted[len(hb):]
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch\ngot:  %x\nwant: %x", got, plaintext)
	}
}
