package dtls

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/logging"
)

func TestSimpleReadWrite(t *testing.T) {
	ca, cb := net.Pipe()
	certificate, privateKey, err := GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	config := &Config{
		Certificate:   certificate,
		PrivateKey:    privateKey,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	}
	gotHello := make(chan struct{})

	go func() {
		server, sErr := testServer(cb, config, false)
		if sErr != nil {
			t.Error(err)
			return
		}
		buf := make([]byte, 1024)
		if _, sErr = server.Read(buf); sErr != nil {
			t.Error(err)
		}
		gotHello <- struct{}{}
	}()

	client, err := testClient(ca, config, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write([]byte("hello")); err != nil {
		t.Error(err)
	}
	select {
	case <-gotHello:
		// OK
	case <-time.After(time.Second * 5):
		t.Error("timeout")
	}
}

func benchmarkConn(b *testing.B, n int64) {
	b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
		ca, cb := net.Pipe()
		certificate, privateKey, err := GenerateSelfSigned()
		config := &Config{Certificate: certificate, PrivateKey: privateKey}
		server := make(chan *Conn)
		go func() {
			s, sErr := testServer(cb, config, false)
			if err != nil {
				b.Error(sErr)
				return
			}
			server <- s
		}()
		if err != nil {
			b.Fatal(err)
		}
		hw := make([]byte, n)
		b.ReportAllocs()
		b.SetBytes(int64(len(hw)))
		go func() {
			client, cErr := testClient(ca, config, false)
			if cErr != nil {
				b.Error(err)
			}
			for {
				if _, cErr = client.Write(hw); cErr != nil {
					b.Error(err)
				}
			}
		}()
		s := <-server
		buf := make([]byte, 2048)
		for i := 0; i < b.N; i++ {
			if _, err = s.Read(buf); err != nil {
				b.Error(err)
			}
		}
	})
}

func BenchmarkConnReadWrite(b *testing.B) {
	for _, n := range []int64{16, 128, 512, 1024, 2048} {
		benchmarkConn(b, n)
	}
}
