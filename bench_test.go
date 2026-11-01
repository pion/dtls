// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"fmt"
	"testing"

	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
)

func benchmarkConn(b *testing.B, payloadSize int64) {
	b.Helper()

	b.Run(fmt.Sprintf("%d", payloadSize), func(b *testing.B) {
		ctx := context.Background()

		ca, cb := packetPipe()
		certificate, err := selfsign.GenerateSelfSigned()
		assert.NoError(b, err)
		server := make(chan *Conn)

		go func() {
			s, sErr := testServer(ctx, cb, cb.RemoteAddr(), []ServerOption{WithCertificates(certificate)}, false)
			assert.NoError(b, sErr)

			server <- s
		}()

		hw := make([]byte, payloadSize)
		b.ReportAllocs()
		b.SetBytes(int64(len(hw)))
		go func() {
			client, cErr := testClient(ctx, ca, ca.RemoteAddr(), []ClientOption{WithInsecureSkipVerify(true)}, false)
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

func BenchmarkHandshakeFragmentFit(b *testing.B) {
	capabilities, err := cryptosuite.NewAEADCapabilities(protocol.Version1_3, maxDTLS13InnerPlaintextLen, 0, 16, 16)
	assert.NoError(b, err)
	for _, tc := range []struct {
		name    string
		mtu     int
		padding uint
		fixed   bool
	}{
		{"FixedPaddingFailure", 80, 100, true},
		{"NormalPadding", 80, 3, false},
		{"UnfitCallback", 80, ^uint(0), false},
		{"LargeMTUCallback", 20000, ^uint(0), false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			conn := &Conn{paddingLengthGenerator: func(uint) uint { return tc.padding }}
			layout := handshakeRecordLayout{capabilities: capabilities, mtu: tc.mtu, headerLen: 5, limit: maxDTLS13InnerPlaintextLen, padded: true}
			length := min(layout.mtu-layout.headerLen-handshake.HeaderLength, maxPlaintextRecordLen-handshake.HeaderLength)
			var fixed *uint
			if tc.fixed {
				fixed = &tc.padding
			}
			b.ReportAllocs()
			for b.Loop() {
				_, _, _ = conn.fitHandshakeFragment(layout, length, fixed)
			}
		})
	}
}
