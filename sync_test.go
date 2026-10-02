// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build go1.25

// Synctest already detects goroutine leaks and deadlocks natively, so test.TimeOut/test.CheckRoutines are intentionally omitted here.

package dtls

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pion/dtls/v4/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/crypto/hash"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/crypto/signature"
	"github.com/pion/dtls/v4/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls12"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
)

func TestReadUnblocksOnClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca, cb, err := pipeMemory()
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, cb.Close())
		}()

		readErr := make(chan error, 1)
		go func() {
			buf := make([]byte, 1)
			_, rErr := ca.Read(buf)
			readErr <- rErr
		}()

		assert.NoError(t, ca.Close())
		assert.NoError(t, ca.Close())

		err = <-readErr
		assert.ErrorIs(t, err, io.EOF)
	})
}

func TestPSKMismatchNoRetransmitLoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		var serverWrites atomic.Int32
		var clientWrites atomic.Int32

		ca, cb := packetPipe()
		defer func() {
			_ = ca.Close()
		}()
		defer func() {
			_ = cb.Close()
		}()

		caCount := &connWithCallback{packetTestConn: ca}
		caCount.onWrite = func([]byte) {
			clientWrites.Add(1)
		}
		cbCount := &connWithCallback{packetTestConn: cb}
		cbCount.onWrite = func([]byte) {
			serverWrites.Add(1)
		}

		clientErr := make(chan error, 1)
		serverErr := make(chan error, 1)

		go func() {
			opts := []ClientOption{WithPSK(func() ([]PSK, error) {
				return []PSK{{Identity: []byte("Client Identity"), Key: []byte("client-psk")}}, nil
			}, nil), WithCipherSuites(cryptosuite.TLS_PSK_WITH_AES_128_CCM_8)}

			c, err := testClient(ctx, caCount, caCount.RemoteAddr(), opts, false)
			if c != nil {
				_ = c.Close() //nolint:contextcheck
			}
			clientErr <- err
		}()

		go func() {
			opts := []ServerOption{WithPSK(nil, func(identities [][]byte) (*PSK, error) {
				return &PSK{Identity: identities[0], Key: []byte("server-psk")}, nil
			}), WithCipherSuites(cryptosuite.TLS_PSK_WITH_AES_128_CCM_8)}

			s, err := testServer(ctx, cbCount, cbCount.RemoteAddr(), opts, false)
			if s != nil {
				_ = s.Close() //nolint:contextcheck
			}
			serverErr <- err
		}()

		serverErrRes := <-serverErr
		clientErrRes := <-clientErr

		assert.ErrorContains(t, serverErrRes, "handshake failed")
		assert.ErrorContains(t, clientErrRes, "handshake failed")

		serverCount := serverWrites.Load()
		clientCount := clientWrites.Load()

		time.Sleep(2 * time.Second)
		synctest.Wait()

		assert.Equal(t, serverCount, serverWrites.Load(), "Server should not retransmit after handshake failure")
		assert.Equal(t, clientCount, clientWrites.Load(), "Client should not retransmit after handshake failure")
		assert.LessOrEqual(t, serverCount, int32(20), "Server retransmit count too high for backoff")
		assert.LessOrEqual(t, clientCount, int32(20), "Client retransmit count too high for backoff")
	})
}

// Assert that plain PSK omits ServerKeyExchange without a server hint.
func TestPSKServerKeyExchange(t *testing.T) { //nolint:cyclop
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		var gotServerKeyExchange atomic.Bool

		clientErr := make(chan error, 1)
		serverHandshakeDone := make(chan struct{})
		ca, cb := packetPipe()
		cbAnalyzer := &connWithCallback{packetTestConn: cb}
		cbAnalyzer.onWrite = func(in []byte) {
			messages, err := recordlayer.UnpackDatagram(in, recordlayer.UnpackDatagramConfig{TargetVersion: protocol.Version1_2})
			assert.NoError(t, err)

			for i := range messages {
				header, err := recordlayer.ParseRecord(messages[i], 0)
				if err != nil {
					continue
				}
				if header.ContentType() != protocol.ContentTypeHandshake || header.Epoch() != 0 {
					continue
				}
				payload := messages[i][recordlayer.FixedHeaderSize:]
				for len(payload) >= handshake.HeaderLength {
					var h handshake.Header
					if err := h.Unmarshal(payload); err != nil {
						break
					}
					if h.Type == handshake.TypeServerKeyExchange {
						gotServerKeyExchange.Store(true)

						break
					}
					fragLen := int(h.FragmentLength)
					if fragLen <= 0 || handshake.HeaderLength+fragLen > len(payload) {
						break
					}
					payload = payload[handshake.HeaderLength+fragLen:]
				}
			}
		}

		go func() {
			opts := []ClientOption{WithPSK(func() ([]PSK, error) {
				return []PSK{{Identity: []byte{0xAB, 0xC1, 0x23}, Key: []byte{0xAB, 0xC1, 0x23}}}, nil
			}, nil), WithCipherSuites(cryptosuite.TLS_PSK_WITH_AES_128_CCM_8)}

			if client, err := testClient(ctx, ca, ca.RemoteAddr(), opts, false); err != nil {
				clientErr <- err
			} else {
				<-serverHandshakeDone
				clientErr <- client.Close() //nolint
			}
		}()

		opts := []ServerOption{WithPSK(nil, func(identities [][]byte) (*PSK, error) {
			return &PSK{Identity: identities[0], Key: []byte{0xAB, 0xC1, 0x23}}, nil
		}), WithCipherSuites(cryptosuite.TLS_PSK_WITH_AES_128_CCM_8)}

		server, err := testServer(ctx, cbAnalyzer, cbAnalyzer.RemoteAddr(), opts, false)
		close(serverHandshakeDone)
		assert.NoError(t, err)

		// Read the value immediately after handshake completes, before closing
		receivedServerKeyExchange := gotServerKeyExchange.Load()

		assert.NoError(t, server.Close())
		if err := <-clientErr; err != nil {
			assert.ErrorIs(t, err, &alertError{&alert.Alert{Level: alert.Warning, Description: alert.CloseNotify}}, "TestPSK: Client error")
		}
		assert.False(t, receivedServerKeyExchange)
	})
}

func TestClientTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		clientErr := make(chan error, 1)

		ca, _ := packetPipe()
		go func() {
			c, err := testClient(ctx, ca, ca.RemoteAddr(), nil, true)
			if err == nil {
				_ = c.Close() //nolint:contextcheck
			}
			clientErr <- err
		}()

		// no server!
		err := <-clientErr
		var netErr net.Error
		assert.ErrorAs(t, err, &netErr, "Client error exp(Temporary network error) failed")
		assert.True(t, netErr.Timeout(), "Client error exp(Timeout) failed")
	})
}

func TestServerTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cookie := make([]byte, 20)
		_, err := rand.Read(cookie)
		assert.NoError(t, err)

		var rand [28]byte
		random := handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand}

		cipherSuites := []cryptosuite.Suite{ciphersuite.ForID(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), ciphersuite.ForID(cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)}

		extensions := []extension.Value{
			&extension.SignatureAlgorithms{
				Schemes: dtlsflight.SignatureSchemeIDs([]signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
					{Hash: hash.SHA384, Signature: signature.ECDSA},
					{Hash: hash.SHA512, Signature: signature.ECDSA},
					{Hash: hash.SHA256, Signature: signature.RSA},
					{Hash: hash.SHA384, Signature: signature.RSA},
					{Hash: hash.SHA512, Signature: signature.RSA},
				}),
			},
			&extension.SupportedGroups{
				Groups: []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384},
			},
			&extension12.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}

		record := &testRecord{
			Header: recordlayer.RecordConfig{
				SequenceNumber: 0,
				Version:        protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				// sequenceNumber and messageSequence line up, may need to be re-evaluated
				Header: handshake.Header{
					MessageSequence: 0,
				},
				Message: &handshake.MessageClientHello{Version: protocol.Version1_2, Cookie: cookie, Random: random, CipherSuiteIDs: cipherSuiteIDs(cipherSuites), CompressionMethods: dtlsflight.DefaultCompressionMethods(), Extensions: extensions},
			},
		}

		packet, err := record.Marshal()
		assert.NoError(t, err)

		ca, cb := packetPipe()
		defer func() {
			assert.NoError(t, ca.Close())
		}()

		// Client reader
		caReadChan := make(chan []byte, 1000)
		go func() {
			for {
				data := make([]byte, 8192)
				n, err := ca.Read(data)
				if err != nil {
					return
				}

				caReadChan <- data[:n]
			}
		}()

		// Start sending ClientHello packets until server responds with first packet
		go func() {
			for {
				select {
				case <-time.After(10 * time.Millisecond):
					_, err := ca.Write(packet)
					if err != nil {
						return
					}
				case <-caReadChan:
					// Once we receive the first reply from the server, stop
					return
				}
			}
		}()

		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()

		serverOpts := []ServerOption{WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), WithFlightInterval(100 * time.Millisecond)}

		_, serverErr := testServer(ctx, cb, cb.RemoteAddr(), serverOpts, true)
		var netErr net.Error
		assert.ErrorAsf(t, serverErr, &netErr, "Client error exp(Temporary network error) failed(%v)", serverErr)
		assert.Truef(t, netErr.Timeout(), "Client error exp(Temporary network error) failed(%v)", serverErr)

		// Wait a little longer to ensure no additional messages have been sent by the server
		time.Sleep(300 * time.Millisecond)
		synctest.Wait()

		select {
		case msg := <-caReadChan:
			assert.Fail(t, "Expected no additional messages from server", "got: %+v", msg)
		default:
		}
	})
}

func TestProtocolVersionValidation(t *testing.T) {
	cookie := make([]byte, 20)
	_, err := rand.Read(cookie)
	assert.NoError(t, err)

	var rand [28]byte
	random := handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand}

	clientOpts := []ClientOption{WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), WithFlightInterval(100 * time.Millisecond)}
	serverOpts := []ServerOption{WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), WithFlightInterval(100 * time.Millisecond)}

	t.Run("Server", func(t *testing.T) {
		serverCases := map[string]struct {
			records []*testRecord
		}{
			"ClientHelloVersion": {
				records: []*testRecord{
					{
						Header: recordlayer.RecordConfig{
							Version: protocol.Version1_2,
						},
						Content: &handshake.Handshake{
							Message: &handshake.MessageClientHello{
								Version:            protocol.Version1_0, // try to downgrade
								Cookie:             cookie,
								Random:             random,
								CipherSuiteIDs:     []uint16{uint16(ciphersuite.ForID(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).ID())},
								CompressionMethods: dtlsflight.DefaultCompressionMethods(),
							},
						},
					},
				},
			},
			"SecondsClientHelloVersion": {
				records: []*testRecord{
					{
						Header: recordlayer.RecordConfig{
							Version: protocol.Version1_2,
						},
						Content: &handshake.Handshake{
							Message: &handshake.MessageClientHello{Version: protocol.Version1_2, Cookie: cookie, Random: random, CipherSuiteIDs: []uint16{uint16(ciphersuite.ForID(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).ID())}, CompressionMethods: dtlsflight.DefaultCompressionMethods()},
						},
					},
					{
						Header: recordlayer.RecordConfig{
							Version:        protocol.Version1_2,
							SequenceNumber: 1,
						},
						Content: &handshake.Handshake{
							Header: handshake.Header{
								MessageSequence: 1,
							},
							Message: &handshake.MessageClientHello{
								Version:            protocol.Version1_0, // try to downgrade
								Cookie:             cookie,
								Random:             random,
								CipherSuiteIDs:     []uint16{uint16(ciphersuite.ForID(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).ID())},
								CompressionMethods: dtlsflight.DefaultCompressionMethods(),
							},
						},
					},
				},
			},
		}
		for name, serverCase := range serverCases {
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ca, cb := packetPipe()
					defer func() {
						assert.NoError(t, ca.Close())
					}()

					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					defer cancel()

					var wg sync.WaitGroup
					wg.Add(1)
					defer wg.Wait()
					go func() {
						defer wg.Done()
						_, err := testServer(
							ctx,
							cb,
							cb.RemoteAddr(),
							serverOpts,
							true,
						)
						assert.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
					}()

					time.Sleep(50 * time.Millisecond)
					synctest.Wait()

					resp := make([]byte, 1024)
					for _, record := range serverCase.records {
						packet, err := record.Marshal()
						assert.NoError(t, err)

						_, werr := ca.Write(packet)
						assert.NoError(t, werr)

						n, rerr := ca.Read(resp[:cap(resp)])
						assert.NoError(t, rerr)

						resp = resp[:n]
					}

					h, parseErr := recordlayer.ParseRecord(resp, 0)
					assert.NoError(t, parseErr)
					assert.Equal(t, protocol.ContentTypeAlert, h.ContentType(), "Peer must return alert to unsupported protocol version")
				})
			})
		}
	})

	t.Run("Client", func(t *testing.T) {
		clientCases := map[string]struct {
			records []*testRecord
		}{
			"ServerHelloVersion": {
				records: []*testRecord{
					{Header: recordlayer.RecordConfig{Version: protocol.Version1_2}, Content: &handshake.Handshake{Message: &handshake.MessageHelloVerifyRequest{Version: protocol.Version1_2, Cookie: cookie}}},
					{
						Header: recordlayer.RecordConfig{
							Version:        protocol.Version1_2,
							SequenceNumber: 1,
						},
						Content: &handshake.Handshake{
							Header: handshake.Header{
								MessageSequence: 1,
							},
							Message: &handshake.MessageServerHello{
								Version: protocol.Version1_0, // try to downgrade
								Random:  random,
								CipherSuiteID: func() *uint16 {
									id := uint16(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)

									return &id
								}(),
								CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
							},
						},
					},
				},
			},
		}
		for name, clientCase := range clientCases {
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ca, cb := packetPipe()
					defer func() {
						assert.NoError(t, ca.Close())
					}()

					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					defer cancel()

					var wg sync.WaitGroup
					wg.Add(1)
					defer wg.Wait()
					go func() {
						defer wg.Done()
						_, err := testClient(ctx, cb, cb.RemoteAddr(), clientOpts, true)
						assert.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
					}()

					time.Sleep(50 * time.Millisecond)
					synctest.Wait()

					for _, record := range clientCase.records {
						_, err := ca.Read(make([]byte, 1024))
						assert.NoError(t, err)

						packet, err := record.Marshal()
						assert.NoError(t, err)

						_, err = ca.Write(packet)
						assert.NoError(t, err)
					}
					resp := make([]byte, 1024)
					n, err := ca.Read(resp)
					assert.NoError(t, err)

					resp = resp[:n]

					h, parseErr := recordlayer.ParseRecord(resp, 0)
					assert.NoError(t, parseErr)
					assert.Equal(t, protocol.ContentTypeAlert, h.ContentType(), "Peer must return alert to unsupported protocol version")
				})
			})
		}
	})
}

// Assert that a DTLS Server only responds with RenegotiationInfo if a ClientHello contained that
// extension according to RFC5746 section 3.6, RFC5246 section 7.4.1.4 and RFC5746 section 4.2.

func TestRenegotiationInfo(t *testing.T) {
	resp := make([]byte, 1024)

	for _, testCase := range []struct {
		Name                     string
		ExpectRenegotiationInfo  bool
		SendRenegotiationInfoExt bool
		IncludeRenegotiationSCSV bool
	}{
		{
			Name:                     "Include RenegotiationInfo",
			ExpectRenegotiationInfo:  true,
			SendRenegotiationInfoExt: true,
		},
		{
			Name:                     "RenegotiationInfo SCSV",
			ExpectRenegotiationInfo:  true,
			IncludeRenegotiationSCSV: true,
		},
		{
			Name:                    "No RenegotiationInfo",
			ExpectRenegotiationInfo: false,
		},
	} {
		test := testCase
		t.Run(test.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ca, cb := packetPipe()
				defer func() {
					assert.NoError(t, ca.Close())
				}()

				ctx := t.Context()

				go func() {
					_, err := testServer(
						ctx,
						cb,
						cb.RemoteAddr(),
						nil,
						true,
					)
					assert.ErrorIs(t, err, context.Canceled)
				}()

				time.Sleep(50 * time.Millisecond)
				synctest.Wait()

				extensions := []extension.Value{}
				if test.SendRenegotiationInfoExt {
					extensions = append(extensions, &extension12.RenegotiationInfo{
						RenegotiatedConnection: 0,
					})
				}
				cipherSuites := cipherSuiteIDs(defaultCipherSuites())
				if test.IncludeRenegotiationSCSV {
					cipherSuites = append(cipherSuites, renegotiationInfoSCSV)
				}
				err := sendClientHello([]byte{}, ca, 0, extensions, cipherSuites...)
				assert.NoError(t, err)

				n, err := ca.Read(resp)
				assert.NoError(t, err)

				_, handshakeRecord := unmarshalHandshakeRecord(t, resp[:n])
				helloVerifyRequest, ok := handshakeRecord.Message.(*handshake.MessageHelloVerifyRequest)
				assert.True(t, ok)

				err = sendClientHello(helloVerifyRequest.Cookie, ca, 1, extensions, cipherSuites...)
				assert.NoError(t, err)

				n, err = ca.Read(resp)
				assert.NoError(t, err)

				messages, err := recordlayer.UnpackDatagram(resp[:n], recordlayer.UnpackDatagramConfig{TargetVersion: protocol.Version1_2})
				assert.NoError(t, err)
				_, handshakeRecord = unmarshalHandshakeRecord(t, messages[0])

				serverHello, ok := handshakeRecord.Message.(*handshake.MessageServerHello)
				assert.True(t, ok)

				actualNegotationInfo := false
				for _, v := range serverHello.Extensions {
					if _, ok := v.(*extension12.RenegotiationInfo); ok {
						actualNegotationInfo = true
					}
				}
				assert.True(t, test.ExpectRenegotiationInfo == actualNegotationInfo, "NegotationInfo state in ServerHello is incorrect: expected(%t) actual(%t)", test.ExpectRenegotiationInfo, actualNegotationInfo)
			})
		})
	}
}

func TestALPNExtension(t *testing.T) {
	for _, test := range []struct {
		Name                   string
		ClientProtocolNameList []string
		ServerProtocolNameList []string
		ExpectedProtocol       string
		ExpectAlertFromClient  bool
		ExpectAlertFromServer  bool
		Alert                  alert.Description
	}{
		{Name: "Negotiate a protocol", ClientProtocolNameList: []string{"http/1.1", "spd/1"}, ServerProtocolNameList: []string{"spd/1"}, ExpectedProtocol: "spd/1", ExpectAlertFromClient: false, ExpectAlertFromServer: false, Alert: 0},
		{Name: "Server doesn't support any", ClientProtocolNameList: []string{"http/1.1", "spd/1"}, ServerProtocolNameList: []string{}, ExpectedProtocol: "", ExpectAlertFromClient: false, ExpectAlertFromServer: false, Alert: 0},
		{Name: "Negotiate with higher server precedence", ClientProtocolNameList: []string{"http/1.1", "spd/1", "http/3"}, ServerProtocolNameList: []string{"ssh/2", "http/3", "spd/1"}, ExpectedProtocol: "http/3", ExpectAlertFromClient: false, ExpectAlertFromServer: false, Alert: 0},
		{Name: "Empty intersection", ClientProtocolNameList: []string{"http/1.1", "http/3"}, ServerProtocolNameList: []string{"ssh/2", "spd/1"}, ExpectedProtocol: "", ExpectAlertFromClient: false, ExpectAlertFromServer: true, Alert: alert.NoApplicationProtocol},
	} {
		t.Run(test.Name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()

				ca, cb := packetPipe()
				go func() {
					var opts []ClientOption
					if len(test.ClientProtocolNameList) > 0 {
						opts = append(opts, WithSupportedProtocols(test.ClientProtocolNameList...))
					}
					_, _ = testClient(ctx, ca, ca.RemoteAddr(), opts, false)
				}()

				// Receive ClientHello
				resp := make([]byte, 1024)
				n, err := cb.Read(resp)
				assert.NoError(t, err)

				ctx2, cancel2 := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel2()

				ca2, cb2 := packetPipe()
				go func() {
					var opts []ServerOption
					if len(test.ServerProtocolNameList) > 0 {
						opts = append(opts, WithSupportedProtocols(test.ServerProtocolNameList...))
					}
					_, err2 := testServer(ctx2, cb2, cb2.RemoteAddr(), opts, true)
					if test.ExpectAlertFromServer {
						assert.NotErrorIs(t, err2, context.Canceled)
					}
				}()

				time.Sleep(50 * time.Millisecond)

				// Forward ClientHello
				_, err = ca2.Write(resp[:n])
				assert.NoError(t, err)

				// Receive HelloVerify
				resp2 := make([]byte, 1024)
				n, err = ca2.Read(resp2)
				assert.NoError(t, err)

				// Forward HelloVerify
				_, err = cb.Write(resp2[:n])
				assert.NoError(t, err)

				// Receive ClientHello
				resp3 := make([]byte, 1024)
				n, err = cb.Read(resp3)
				assert.NoError(t, err)

				// Forward ClientHello
				_, err = ca2.Write(resp3[:n])
				assert.NoError(t, err)

				// Receive ServerHello
				resp4 := make([]byte, 1024)
				n, err = ca2.Read(resp4)
				assert.NoError(t, err)

				messages, err := recordlayer.UnpackDatagram(resp4[:n], recordlayer.UnpackDatagramConfig{TargetVersion: protocol.Version1_2})
				assert.NoError(t, err)

				if test.ExpectAlertFromServer { //nolint:nestif
					a := unmarshalAlertRecord(t, messages[0])
					assert.Equalf(t, test.Alert, a.Description, "ALPN %v", test.Name)
				} else {
					recordHeader, handshakeRecord := unmarshalHandshakeRecord(t, messages[0])
					serverHello, ok := handshakeRecord.Message.(*handshake.MessageServerHello)
					assert.True(t, ok)

					var negotiatedProtocol string
					for i, v := range serverHello.Extensions {
						if _, ok := v.(*extension.ALPNSelection); ok {
							e, ok := v.(*extension.ALPNSelection)
							assert.True(t, ok)

							negotiatedProtocol = e.Protocol

							// Manipulate ServerHello
							if test.ExpectAlertFromClient {
								serverHello.Extensions[i] = extension.Raw{Type: extension.TypeALPN, Data: []byte{0x00, 0x08, 0x02, 'h', '2', 0x04, 'o', 'o', 'p', 's'}}
							}
						}
					}

					assert.Equalf(t, test.ExpectedProtocol, negotiatedProtocol, "ALPN %v", test.Name)

					s, err := marshalTestRecord(recordlayer.RecordConfig{Version: recordHeader.Version(), Epoch: recordHeader.Epoch(), SequenceNumber: recordHeader.SequenceNumber(), ConnectionID: recordHeader.ConnectionID()}, handshakeRecord)
					assert.NoError(t, err)

					// Forward ServerHello
					_, err = cb.Write(s)
					assert.NoError(t, err)

					if test.ExpectAlertFromClient {
						resp5 := make([]byte, 1024)
						n, err = cb.Read(resp5)
						assert.NoError(t, err)

						a := unmarshalAlertRecord(t, resp5[:n])
						assert.Equalf(t, test.Alert, a.Description, "ALPN %v", test.Name)
					}
				}

				time.Sleep(50 * time.Millisecond) // Give some time for returned errors
				synctest.Wait()
			})
		})
	}
}

// Make sure the supported_groups extension is not included in the ServerHello.
func TestSupportedGroupsExtension(t *testing.T) {
	t.Run("ServerHello Supported Groups", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			ca, cb := packetPipe()
			go func() {
				_, err := testServer(ctx, cb, cb.RemoteAddr(), nil, true)
				assert.ErrorIs(t, err, context.Canceled)
			}()
			extensions := []extension.Value{&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384}}, &extension12.SupportedPointFormats{PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed}}}

			time.Sleep(50 * time.Millisecond)

			resp := make([]byte, 1024)
			err := sendClientHello([]byte{}, ca, 0, extensions)
			assert.NoError(t, err)

			// Receive ServerHello
			n, err := ca.Read(resp)
			assert.NoError(t, err)

			_, handshakeRecord := unmarshalHandshakeRecord(t, resp[:n])

			helloVerifyRequest, ok := handshakeRecord.Message.(*handshake.MessageHelloVerifyRequest)
			assert.True(t, ok, "Failed to cast MessageHelloVerifyRequest")

			err = sendClientHello(helloVerifyRequest.Cookie, ca, 1, extensions)
			assert.NoError(t, err)

			n, err = ca.Read(resp)
			assert.NoError(t, err)

			messages, err := recordlayer.UnpackDatagram(resp[:n], recordlayer.UnpackDatagramConfig{TargetVersion: protocol.Version1_2})
			assert.NoError(t, err)
			_, handshakeRecord = unmarshalHandshakeRecord(t, messages[0])

			serverHello, ok := handshakeRecord.Message.(*handshake.MessageServerHello)
			assert.True(t, ok, "TestSupportedGroups: Failed to cast MessageServerHello")

			gotGroups := false
			for _, v := range serverHello.Extensions {
				if _, ok := v.(*extension.SupportedGroups); ok {
					gotGroups = true
				}
			}

			assert.False(t, gotGroups, "TestSupportedGroups: supported_groups extension was sent in ServerHello")
		})
	})
}

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
