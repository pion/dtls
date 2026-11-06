// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build go1.25

// Synctest already detects goroutine leaks and deadlocks natively, so test.TimeOut/test.CheckRoutines are intentionally omitted here.

package dtls

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

type finishedACKTestConn struct {
	net.PacketConn
	server   *Conn
	sequence uint64
	acks     atomic.Int32
}

func (c *finishedACKTestConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	if len(data) != 0 && protocol.IsDTLS13Ciphertext(protocol.ContentType(data[0])) && data[0]&3 == 3 {
		record, err := recordlayer.ParseRecord(data, 0)
		if err != nil {
			return 0, err
		}
		generation, err := c.server.writeTrafficGeneration(3)
		if err != nil {
			return 0, err
		}
		protection := testRecordProtection13{TrafficProtection: generation.Protection, capabilities: dtlsstate.CommonState(c.server.state).CipherSuite.Capabilities()}
		header := recordlayer.CiphertextConfig{EpochLow: 3, SequenceNumber: uint16(record.SequenceNumber() & 0xffff), TwoByteSequence: record.SequenceBytes() == 2, LengthPresent: record.LengthPresent()}
		opened, err := protection.OpenRecord(header, c.sequence, record.Payload())
		c.sequence++
		if err != nil {
			return 0, err
		}
		if opened.RealType == protocol.ContentTypeACK && c.acks.Add(1) == 1 {
			return len(data), nil
		}
	}

	return c.PacketConn.WriteTo(data, addr)
}

func TestClientHandshakeCompletesBeforeFinishedACK(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		certificate, err := selfsign.GenerateSelfSigned()
		require.NoError(t, err)
		clientTransport, serverTransport := packetPipe()
		filtered := &finishedACKTestConn{PacketConn: serverTransport}
		client, err := Client(clientTransport, clientTransport.RemoteAddr(),
			WithInsecureSkipVerify(true), WithMinVersion(protocol.Version1_3), WithFlightInterval(time.Second))
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })
		server, err := Server(filtered, serverTransport.RemoteAddr(), WithCertificates(certificate),
			WithMinVersion(protocol.Version1_3), WithFlightInterval(time.Second))
		require.NoError(t, err)
		t.Cleanup(func() { _ = server.Close() })
		filtered.server = server

		// Finish the handshake and key update before Finished can be retransmitted.
		started := time.Now()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second/2)
		defer cancel()
		done := make(chan error, 2)
		go func() { done <- client.HandshakeContext(ctx) }()
		go func() { done <- server.HandshakeContext(ctx) }()
		require.NoError(t, <-done)
		require.NoError(t, <-done)
		require.NoError(t, client.UpdateKeys(ctx, KeyUpdateOptions{}))
		_, err = client.Write([]byte("application data"))
		require.NoError(t, err)
		buffer := make([]byte, 64)
		n, err := server.Read(buffer)
		require.NoError(t, err)
		require.Equal(t, "application data", string(buffer[:n]))
		require.Less(t, time.Since(started), time.Second)
		cancel() // Completion must leave retransmissions independent of this context.

		acks := filtered.acks.Load()
		time.Sleep(time.Second)
		synctest.Wait()
		require.Greater(t, filtered.acks.Load(), acks, "Finished must still be retransmitted")
		state, ok := client.ConnectionState()
		require.True(t, ok)
		require.Equal(t, uint64(4), state.KeyUsage.WriteEpoch, "Finished retransmission must preserve updated keys")
		acks = filtered.acks.Load()
		time.Sleep(4 * time.Second)
		synctest.Wait()
		require.Equal(t, acks, filtered.acks.Load(), "ACK must stop final-flight retransmission")
	})
}
