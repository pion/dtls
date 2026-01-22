// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/logging"
	"github.com/pion/transport/v4/dpipe"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
)

func TestSimpleReadWrite(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := dpipe.Pipe()
	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	gotHello := make(chan struct{})

	go func() {
		server, sErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
			Certificates:  []tls.Certificate{certificate},
			LoggerFactory: logging.NewDefaultLoggerFactory(),
		}, false)
		assert.NoError(t, sErr)

		buf := make([]byte, 1024)
		_, sErr = server.Read(buf) //nolint:contextcheck
		assert.NoError(t, sErr)

		gotHello <- struct{}{}
		assert.NoError(t, server.Close()) //nolint:contextcheck
	}()

	client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
		LoggerFactory:      logging.NewDefaultLoggerFactory(),
		InsecureSkipVerify: true,
	}, false)
	assert.NoError(t, err)
	_, err = client.Write([]byte("hello"))
	assert.NoError(t, err)
	select {
	case <-gotHello:
		// OK
	case <-time.After(time.Second * 5):
		assert.Fail(t, "timeout")
	}
	assert.NoError(t, client.Close())
}

func benchmarkConn(b *testing.B, payloadSize int64) {
	b.Helper()

	b.Run(fmt.Sprintf("%d", payloadSize), func(b *testing.B) {
		ctx := context.Background()

		ca, cb := dpipe.Pipe()
		certificate, err := selfsign.GenerateSelfSigned()
		assert.NoError(b, err)
		server := make(chan *Conn)

		go func() {
			s, sErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
				Certificates: []tls.Certificate{certificate},
			}, false)
			assert.NoError(b, sErr)

			server <- s
		}()

		hw := make([]byte, payloadSize)
		b.ReportAllocs()
		b.SetBytes(int64(len(hw)))
		go func() {
			client, cErr := testClient(
				ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{InsecureSkipVerify: true}, false,
			)
			assert.NoError(b, cErr)
			for {
				_, cErr = client.Write(hw) //nolint:contextcheck
				assert.NoError(b, cErr)
			}
		}()
		s := <-server
		buf := make([]byte, 2048)
		for i := 0; i < b.N; i++ {
			_, err = s.Read(buf)
			assert.NoError(b, err)
		}
	})
}

func BenchmarkConnReadWrite(b *testing.B) {
	for _, n := range []int64{16, 128, 512, 1024, 2048} {
		benchmarkConn(b, n)
	}
}
