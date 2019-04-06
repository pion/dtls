package dtls

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestResumeClient(t *testing.T) {
	DoTestResume(t, Client, Server)
}

func TestResumeServer(t *testing.T) {
	DoTestResume(t, Server, Client)
}

func fatal(t *testing.T, errChan chan error, err error) {
	close(errChan)
	t.Fatal(err)
}

func DoTestResume(t *testing.T, newLocal, newRemote func(net.Conn, *Config) (*Conn, error)) {
	certificate, privateKey, err := GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	// Generate connections
	localConn1, rc1 := net.Pipe()
	localConn2, rc2 := net.Pipe()
	remoteConn := &backupConn{curr: rc1, next: rc2}

	// Launch remote in another goroutine
	errChan := make(chan error, 1)
	defer func() {
		err = <-errChan
		if err != nil {
			t.Fatal(err)
		}
	}()
	config := &Config{Certificate: certificate, PrivateKey: privateKey}
	go func() {
		var remote *Conn
		var errR error
		remote, errR = newRemote(remoteConn, config)
		if errR != nil {
			errChan <- errR
		}

		// Loop of read write
		for i := 0; i < 2; i++ {
			recv := make([]byte, 1024)
			var n int
			n, errR = remote.Read(recv)
			if errR != nil {
				errChan <- errR
			}

			if _, errR = remote.Write(recv[:n]); errR != nil {
				errChan <- errR
			}
		}
		errChan <- nil
	}()

	var local *Conn
	local, err = newLocal(localConn1, config)
	if err != nil {
		fatal(t, errChan, err)
	}

	// Test write and read
	message := []byte("Hello")
	if _, err = local.Write(message); err != nil {
		fatal(t, errChan, err)
	}

	recv := make([]byte, 1024)
	var n int
	n, err = local.Read(recv)
	if err != nil {
		fatal(t, errChan, err)
	}

	if !bytes.Equal(message, recv[:n]) {
		fatal(t, errChan, fmt.Errorf("messages missmatch: %s != %s", message, recv[:n]))
	}

	// Export dtls connection
	var state *State
	var innerConn net.Conn
	state, innerConn, err = local.Export()
	if err != nil {
		fatal(t, errChan, err)
	}
	if err = innerConn.Close(); err != nil {
		fatal(t, errChan, err)
	}

	// Serialize and deserialize state
	var b []byte
	b, err = state.MarshalBinary()
	if err != nil {
		fatal(t, errChan, err)
	}
	deserialized := &State{}
	if err = deserialized.UnmarshalBinary(b); err != nil {
		fatal(t, errChan, err)
	}

	// Resume dtls connection
	var resumed net.Conn
	resumed, err = Resume(state, localConn2, config)
	if err != nil {
		fatal(t, errChan, err)
	}

	// Test write and read on resumed connection
	if _, err = resumed.Write(message); err != nil {
		fatal(t, errChan, err)
	}

	recv = make([]byte, 1024)
	n, err = resumed.Read(recv)
	if err != nil {
		fatal(t, errChan, err)
	}

	if !bytes.Equal(message, recv[:n]) {
		fatal(t, errChan, fmt.Errorf("messages missmatch: %s != %s", message, recv[:n]))
	}
}

type backupConn struct {
	curr net.Conn
	next net.Conn
	mux  sync.Mutex
}

func (b *backupConn) Read(data []byte) (n int, err error) {
	n, err = b.curr.Read(data)
	if err != nil && b.next != nil {
		b.mux.Lock()
		b.curr = b.next
		b.next = nil
		b.mux.Unlock()
		return b.Read(data)
	}
	return n, err
}

func (b *backupConn) Write(data []byte) (n int, err error) {
	n, err = b.curr.Write(data)
	if err != nil && b.next != nil {
		b.mux.Lock()
		b.curr = b.next
		b.next = nil
		b.mux.Unlock()
		return b.Write(data)
	}
	return n, err
}

func (b *backupConn) Close() error {
	return nil
}

func (b *backupConn) LocalAddr() net.Addr {
	return nil
}

func (b *backupConn) RemoteAddr() net.Addr {
	return nil
}

func (b *backupConn) SetDeadline(t time.Time) error {
	return nil
}

func (b *backupConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (b *backupConn) SetWriteDeadline(t time.Time) error {
	return nil
}
