package dtls

import (
	"os"
	"reflect"
	"testing"
	"time"
)

func TestFileSessionStoreClient(t *testing.T) {
	root, err := os.MkdirTemp(os.TempDir(), "dtls")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	fs := FileSessionStore{Root: root}

	s := &Session{
		ID:     []byte{0xab},
		Secret: []byte{0xcd},
		Addr:   "1.1.1.1:1",
	}
	fs.Set(s, true)

	s2 := fs.GetByAddr("1.1.1.1:1")
	if !reflect.DeepEqual(s, s2) {
		t.Fatalf("get session failed")
	}
	s3 := fs.Get([]byte{0xab})
	if !reflect.DeepEqual(s, s3) {
		t.Fatalf("get session failed")
	}

	fs.Del(s.ID)
	if fs.Get([]byte{0xab}) != nil || fs.GetByAddr("1.1.1.1:1") != nil {
		t.Fatal("del failed")
	}
}

func TestFileSessionStore(t *testing.T) {
	root, err := os.MkdirTemp(os.TempDir(), "dtls")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	fs := FileSessionStore{Root: root}

	s := &Session{
		ID:     []byte{0xab},
		Secret: []byte{0xcd},
		Addr:   "1.1.1.1:2",
	}
	fs.Set(s, false)

	if fs.GetByAddr("1.1.1.1:1") != nil {
		t.Fatalf("server should not save by addr")
	}
	s3 := fs.Get([]byte{0xab})
	if !reflect.DeepEqual(s, s3) {
		t.Fatalf("get session failed")
	}
}

func TestFileSessionStoreTTL(t *testing.T) {
	root, err := os.MkdirTemp(os.TempDir(), "dtls")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	fs := FileSessionStore{Root: root, TTL: 100 * time.Millisecond}

	s := &Session{
		ID:     []byte{0xab},
		Secret: []byte{0xcd},
		Addr:   "1.1.1.1:1",
	}
	fs.Set(s, false)

	s3 := fs.Get([]byte{0xab})
	if !reflect.DeepEqual(s, s3) {
		t.Fatalf("get session failed")
	}

	time.Sleep(150 * time.Millisecond)
	if fs.Get([]byte{0xab}) != nil {
		t.Fatal("ttl does not work")
	}
}
