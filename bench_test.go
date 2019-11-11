package dtls

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/test"
)

func TestSimpleReadWrite(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	ca, cb := net.Pipe()
	certificate, err := GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	gotHello := make(chan struct{})

	go func() {
		server, sErr := testServer(cb, &Config{
			Certificate:   certificate,
			LoggerFactory: logging.NewDefaultLoggerFactory(),
		}, false)
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

	client, err := testClient(ca, &Config{
		LoggerFactory:      logging.NewDefaultLoggerFactory(),
		InsecureSkipVerify: true,
	}, false)
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

	if err = ca.Close(); err != nil {
		t.Error(err)
	} else if err = cb.Close(); err != nil {
		t.Error(err)
	}
}

func benchmarkConn(b *testing.B, n int64) {
	b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
		ca, cb := net.Pipe()
		certificate, err := GenerateSelfSigned()
		server := make(chan *Conn)
		go func() {
			s, sErr := testServer(cb, &Config{
				Certificate: certificate,
			}, false)
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
			client, cErr := testClient(ca, &Config{InsecureSkipVerify: true}, false)
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
