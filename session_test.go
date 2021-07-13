package dtls

import (
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"sync"
	"testing"
)

func getFSS(t *testing.T) *FileSessionStore {
	root, err := os.MkdirTemp(os.TempDir(), "pion-dtls-")
	if err != nil {
		t.Fatal(err)
	}

	return &FileSessionStore{Root: root}
}

func TestSessionResumption(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}

	fss1 := getFSS(t)
	fss2 := getFSS(t)

	defer os.RemoveAll(fss1.Root)
	defer os.RemoveAll(fss2.Root)

	id, _ := hex.DecodeString("9b9fc92255634d9fb109febed42166717bb8ded8c738ba71bc7f2a0d9dae0306")
	secret, _ := hex.DecodeString("2e942a37aca5241deb2295b5fcedac221c7078d2503d2b62aeb48c880d7da73c001238b708559686b9da6e829c05ead7")

	s := Session{
		ID:     id,
		Secret: secret,
		Addr:   addr.String(),
	}

	fss1.Set(&s, false)
	fss2.Set(&s, true)

	cfg1 := Config{
		PSK: func(hint []byte) ([]byte, error) {
			return []byte{0xAB, 0xC1, 0x23}, nil
		},
		PSKIdentityHint: []byte("Pion DTLS Client"),
		CipherSuites:    []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256},
		SessionStore:    fss1,
	}

	cfg2 := cfg1
	cfg2.SessionStore = fss2
	cfg2.PSK = func([]byte) ([]byte, error) { return []byte{}, nil }

	var wg sync.WaitGroup
	var buf [4]byte

	wg.Add(2)

	go func() {
		defer wg.Done()

		listener, err := Listen("udp", addr, &cfg1)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()

		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		_, err = conn.Read(buf[:])
		if err != nil {
			t.Fatal(err)
		}
	}()

	go func() {
		defer wg.Done()

		conn, err := Dial("udp", addr, &cfg2)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		_, err = conn.Write([]byte("dtls"))
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(secret, conn.state.masterSecret) {
			t.Fatalf("invalid master sercret: %x", conn.state.masterSecret)
		}

		if !bytes.Equal(id, conn.state.SessionID) {
			t.Fatalf("invalid session id: %x", conn.state.SessionID)
		}
	}()
	wg.Wait()

	if string(buf[:]) != "dtls" {
		t.Fatal("error")
	}
}
