// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build go1.25

// Synctest already detects goroutine leaks and deadlocks natively, so test.TimeOut/test.CheckRoutines are intentionally omitted here.

package dtls

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
)

// Assert that a DTLS Server only responds with RenegotiationInfo if a ClientHello contained that
// extension according to RFC5746 section 3.6, RFC5246 section 7.4.1.4 and RFC5746 section 4.2.

func TestApplicationDataQueueLimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		ca, cb := packetPipe()
		defer func() {
			assert.NoError(t, ca.Close())
		}()
		defer func() {
			assert.NoError(t, cb.Close())
		}()

		done := make(chan struct{})
		go func() {
			serverCert, err := selfsign.GenerateSelfSigned()
			assert.NoError(t, err)

			dconn, err := Server(cb, cb.RemoteAddr(), WithCertificates(serverCert))
			assert.NoError(t, err)

			go func() {
				for range 5 {
					select {
					case <-done:
						return
					case <-time.After(1 * time.Second):
					}
					dconn.lock.RLock()
					qlen := len(dconn.encryptedPackets)
					dconn.lock.RUnlock()
					assert.GreaterOrEqual(t, maxAppDataPacketQueueSize, qlen, "too many encrypted packets enqueued")
				}
			}()
			assert.Error(t, dconn.HandshakeContext(ctx))
			close(done)
		}()
		extensions := []extension.Value{}

		time.Sleep(50 * time.Millisecond)

		assert.NoError(t, sendClientHello([]byte{}, ca, 0, extensions))

		time.Sleep(50 * time.Millisecond)

		for i := range 1000 {
			// Send an application data packet
			packet, err := marshalTestRecord(recordlayer.RecordConfig{
				Version:        protocol.Version1_2,
				SequenceNumber: uint64(3),
				Epoch:          1, // use an epoch greater than 0
			}, &protocol.ApplicationData{
				Data: []byte{1, 2, 3, 4},
			})
			assert.NoError(t, err)
			_, err = ca.Write(packet)
			assert.NoError(t, err)
			if i%100 == 0 {
				time.Sleep(10 * time.Millisecond)
			}
		}
		time.Sleep(1 * time.Second)
		assert.NoError(t, ca.Close())
		<-done
		synctest.Wait()
	})
}
