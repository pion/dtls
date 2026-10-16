// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	dtlsflight12 "github.com/pion/dtls/v4/internal/flight/flight12"
	dtlshandshake "github.com/pion/dtls/v4/internal/handshake"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/logging"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nonZeroRetransmitInterval = 100 * time.Millisecond

// Test that writes to the key log are in the correct format and only applies
// when a key log writer is given.
func TestWriteKeyLog(t *testing.T) {
	var buf bytes.Buffer
	cfg := dtlsconfig.HandshakeConfig{
		KeyLogWriter: &buf,
	}
	cfg.WriteKeyLog("LABEL", []byte{0xAA, 0xBB, 0xCC}, []byte{0xDD, 0xEE, 0xFF})

	// Secrets follow the format <Label> <space> <ClientRandom> <space> <Secret>
	// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
	want := "LABEL aabbcc ddeeff\n"
	assert.Equal(t, want, buf.String())

	// no key log writer = no writes
	cfg = dtlsconfig.HandshakeConfig{}
	cfg.WriteKeyLog("LABEL", []byte{0xAA, 0xBB, 0xCC}, []byte{0xDD, 0xEE, 0xFF})
}

func TestHandshaker(t *testing.T) { //nolint:cyclop
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logging.NewDefaultLoggerFactory()
	logger := loggerFactory.NewLogger("dtls")

	cipherSuites, err := selectCipherSuites(
		nil, nil, true, false, protocol.Version1_2, protocol.Version1_2,
	)
	assert.NoError(t, err)
	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	genFilters := map[string]func() (TestEndpoint, TestEndpoint, func(t *testing.T)){
		"PassThrough": func() (TestEndpoint, TestEndpoint, func(t *testing.T)) {
			return TestEndpoint{}, TestEndpoint{}, nil
		},

		"HelloVerifyRequestLost": func() (TestEndpoint, TestEndpoint, func(t *testing.T)) {
			var (
				cntHelloVerifyRequest  = 0
				cntClientHelloNoCookie = 0
			)
			const helloVerifyDrop = 5

			clientEndpoint := TestEndpoint{
				Filter: filterHandshakeMessage(func(message handshake.Message) bool {
					if hmch, ok := message.(*handshake.MessageClientHello); ok {
						if len(hmch.Cookie) == 0 {
							cntClientHelloNoCookie++
						}
					}

					return true
				}),
			}

			serverEndpoint := TestEndpoint{
				Filter: filterHandshakeMessage(func(message handshake.Message) bool {
					if _, ok := message.(*handshake.MessageHelloVerifyRequest); ok {
						cntHelloVerifyRequest++

						return cntHelloVerifyRequest > helloVerifyDrop
					}

					return true
				}),
			}

			report := func(t *testing.T) {
				t.Helper()

				assert.Equal(t, cntHelloVerifyRequest, helloVerifyDrop+1, "Number of HelloVerifyRequest retransmit is wrong")
				assert.Equal(t, cntHelloVerifyRequest, cntClientHelloNoCookie, "Number of ClientHello without cookie should match the number of HelloVerifyRequest sent.")
			}

			return clientEndpoint, serverEndpoint, report
		},

		"NoLatencyTest": func() (TestEndpoint, TestEndpoint, func(t *testing.T)) {
			var (
				cntClientFinished = 0
				cntServerFinished = 0
			)

			clientEndpoint := TestEndpoint{
				Filter: filterHandshakeMessage(func(message handshake.Message) bool {
					if _, ok := message.(*handshake.MessageFinished); ok {
						cntClientFinished++
					}

					return true
				}),
			}

			serverEndpoint := TestEndpoint{
				Filter: filterHandshakeMessage(func(message handshake.Message) bool {
					if _, ok := message.(*handshake.MessageFinished); ok {
						cntServerFinished++
					}

					return true
				}),
			}

			report := func(t *testing.T) {
				t.Helper()

				assert.Equal(t, 1, cntClientFinished)
				assert.Equal(t, 1, cntServerFinished)
			}

			return clientEndpoint, serverEndpoint, report
		},

		"SlowServerTest": func() (TestEndpoint, TestEndpoint, func(t *testing.T)) {
			var (
				cntClientFinished               = 0
				isClientFinished                atomic.Bool
				cntClientFinishedLastRetransmit = 0
				cntServerFinished               = 0
				isServerFinished                atomic.Bool
				cntServerFinishedLastRetransmit = 0
			)

			clientEndpoint := TestEndpoint{
				Filter: filterHandshakeMessage(func(message handshake.Message) bool {
					if _, ok := message.(*handshake.MessageFinished); ok {
						if isClientFinished.Load() {
							cntClientFinishedLastRetransmit++
						} else {
							cntClientFinished++
						}
					}

					return true
				}),
				Delay: 0,
				OnFinished: func() {
					isClientFinished.Store(true)
				},
				FinishWait: 2000 * time.Millisecond,
			}

			serverEndpoint := TestEndpoint{
				Filter: filterHandshakeMessage(func(message handshake.Message) bool {
					if _, ok := message.(*handshake.MessageFinished); ok {
						if isServerFinished.Load() {
							cntServerFinishedLastRetransmit++
						} else {
							cntServerFinished++
						}
					}

					return true
				}),
				Delay: 1000 * time.Millisecond,
				OnFinished: func() {
					isServerFinished.Store(true)
				},
				FinishWait: 2000 * time.Millisecond,
			}

			report := func(t *testing.T) {
				t.Helper()

				// with one second server delay and 100 ms retransmit (+ exponential backoff),
				// there should be close to 4 `Finished` from client
				// using a range of 3 - 5 for checking.
				assert.LessOrEqual(t, 3, cntClientFinished, "Number of client finished should be greater than 3")
				assert.GreaterOrEqual(t, 5, cntClientFinished, "Number of client finished should be less than 5")
				assert.True(t, isClientFinished.Load())
				// there should be no `Finished` last retransmit from client
				assert.Equal(t, 0, cntClientFinishedLastRetransmit, "Number of client finished last retransmit greater than zero")
				assert.LessOrEqual(t, 1, cntServerFinished, "Number of server finished less than 1")
				assert.True(t, isServerFinished.Load())
				// there should be `Finished` last retransmit from server.
				// Because of slow server, client would have sent several `Finished`.
				assert.LessOrEqual(t, 1, cntServerFinished, "Number of server finished last retransmit is less than 1")
			}

			return clientEndpoint, serverEndpoint, report
		},

		"RetransmitFinishedMessageLost": func() (TestEndpoint, TestEndpoint, func(t *testing.T)) { //nolint:unparam
			serverEndpoint := TestEndpoint{
				Retransmit: func(p *dtlsflight.Outbound) bool {
					h, ok := p.Content.(*handshake.Handshake)
					if !ok {
						return false
					}
					_, isFinished := h.Message.(*handshake.MessageFinished)

					return isFinished
				},
			}
			// If retransmit causes Finished to be lost, this will hang until timeout.
			return TestEndpoint{}, serverEndpoint, nil
		},
	}

	for name, filters := range genFilters {
		clientEndpoint, serverEndpoint, report := filters()
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			if report != nil {
				defer report(t)
			}

			ca, cb := flightTestPipe(ctx, clientEndpoint, serverEndpoint)
			ca.state.IsClient = true

			var wg sync.WaitGroup
			wg.Add(2)

			ctxCliFinished, cancelCli := context.WithCancel(ctx)
			ctxSrvFinished, cancelSrv := context.WithCancel(ctx)
			go func() {
				defer wg.Done()
				runHandshakeFSM12ForTest(t, ctx, ca, cipherSuites, clientCert, logger, clientEndpoint, cancelCli, dtlsflight12.Flight1)
			}()

			go func() {
				defer wg.Done()
				runHandshakeFSM12ForTest(t, ctx, cb, cipherSuites, clientCert, logger, serverEndpoint, cancelSrv, dtlsflight12.Flight0)
			}()

			<-ctxCliFinished.Done()
			<-ctxSrvFinished.Done()

			cancel()
			wg.Wait()
		})
	}
}

func filterHandshakeMessage(filter func(handshake.Message) bool) func(*dtlsflight.Outbound) bool {
	return func(packet *dtlsflight.Outbound) bool {
		handshakePacket, ok := packet.Content.(*handshake.Handshake)

		return !ok || filter(handshakePacket.Message)
	}
}

func runHandshakeFSM12ForTest(t *testing.T, ctx context.Context, conn *flightTestConn, cipherSuites []dtlsconfig.CipherSuite, clientCert tls.Certificate, logger logging.LeveledLogger, endpoint TestEndpoint, cancel func(), initialFlight dtlsflight12.Flight) {
	t.Helper()

	cfg := &dtlsconfig.HandshakeConfig{LocalCipherSuites: cipherSuites, LocalCertificates: []tls.Certificate{clientCert}, EllipticCurves: defaultCurves, LocalSignatureSchemes: signaturehash.Algorithms(), InsecureSkipVerify: true, Log: logger, InitialRetransmitInterval: nonZeroRetransmitInterval}
	establishment := dtlshandshake.NewEstablishment()
	go func() {
		select {
		case <-establishment.Done():
			if endpoint.OnFinished != nil {
				endpoint.OnFinished()
			}
			time.AfterFunc(endpoint.FinishWait, cancel)
		case <-ctx.Done():
		}
	}()

	fsm := dtlshandshake.NewFSM12(&conn.state, conn.handshakeCache, cfg, initialFlight, nil, establishment)
	err := fsm.Run(ctx, conn, dtlshandshake.StatePreparing)
	switch {
	case errors.Is(err, context.Canceled):
	case errors.Is(err, context.DeadlineExceeded):
		assert.Fail(t, "timeout")
	default:
		assert.Failf(t, "Handshake failed", "Error: %v", err)
	}
}

type packetFilter func(p *dtlsflight.Outbound) bool

type TestEndpoint struct {
	Filter     packetFilter
	Retransmit packetFilter // force isRetransmit=true when matched
	Delay      time.Duration
	OnFinished func()
	FinishWait time.Duration
}

func flightTestPipe(ctx context.Context, clientEndpoint TestEndpoint, serverEndpoint TestEndpoint) (*flightTestConn, *flightTestConn) {
	ca := dtlsflight.NewCache()
	cb := dtlsflight.NewCache()
	chA := make(chan dtlshandshake.RecvHandshakeState)
	chB := make(chan dtlshandshake.RecvHandshakeState)

	return &flightTestConn{
			state:          dtlsstate.NewState12(false),
			handshakeCache: ca,
			otherEndCache:  cb,
			recv:           chA,
			otherEndRecv:   chB,
			done:           ctx.Done(),
			filter:         clientEndpoint.Filter,
			retransmit:     clientEndpoint.Retransmit,
			delay:          clientEndpoint.Delay,
		}, &flightTestConn{
			state:          dtlsstate.NewState12(false),
			handshakeCache: cb,
			otherEndCache:  ca,
			recv:           chB,
			otherEndRecv:   chA,
			done:           ctx.Done(),
			filter:         serverEndpoint.Filter,
			retransmit:     serverEndpoint.Retransmit,
			delay:          serverEndpoint.Delay,
		}
}

type flightTestConn struct {
	state          dtlsstate.State
	handshakeCache *dtlsflight.Cache
	recv           chan dtlshandshake.RecvHandshakeState
	done           <-chan struct{}
	epoch          uint64

	filter     packetFilter
	retransmit packetFilter

	delay time.Duration

	otherEndCache *dtlsflight.Cache
	otherEndRecv  chan dtlshandshake.RecvHandshakeState
}

func (c *flightTestConn) RecvHandshake() <-chan dtlshandshake.RecvHandshakeState {
	return c.recv
}

func (c *flightTestConn) SetLocalEpoch(epoch uint64) {
	c.epoch = epoch
}

func (c *flightTestConn) Notify(context.Context, alert.Level, alert.Description) error {
	return nil
}

func (c *flightTestConn) WritePackets( //nolint:cyclop
	_ context.Context,
	pkts []*dtlsflight.Outbound,
) (*dtlshandshake.WriteResult, error) {
	time.Sleep(c.delay)
	isRetransmit := false
	isClientHelloRetransmit := false
	for _, pkt := range pkts {
		if c.filter != nil && !c.filter(pkt) {
			continue
		}
		if c.retransmit != nil && c.retransmit(pkt) {
			isRetransmit = true
		}
		if handshake, ok := pkt.Content.(*handshake.Handshake); ok {
			handshakeRaw, err := handshake.Marshal()
			if err != nil {
				return nil, err
			}

			c.handshakeCache.Push(handshakeRaw, pkt.Epoch, handshake.Header.MessageSequence, handshake.Header.Type, c.state.IsClient)

			content, err := handshake.Message.Marshal()
			if err != nil {
				return nil, err
			}
			handshake.Header.Length = uint32(len(content))         //nolint:gosec // G115
			handshake.Header.FragmentLength = uint32(len(content)) //nolint:gosec // G115
			hdr, err := handshake.Header.Marshal()
			if err != nil {
				return nil, err
			}
			hdr = append(hdr, content...)
			if c.state.IsClient && pkt.Epoch == 0 {
				isClientHelloRetransmit = isClientHelloRetransmit || c.otherEndCache.IsClientHelloRetransmit(hdr)
			}
			c.otherEndCache.Push(hdr, pkt.Epoch, handshake.Header.MessageSequence, handshake.Header.Type, c.state.IsClient)
		}
	}
	go func() {
		select {
		case c.otherEndRecv <- dtlshandshake.RecvHandshakeState{Done: make(chan struct{}), IsRetransmit: isRetransmit, IsClientHelloRetransmit: isClientHelloRetransmit}:
		case <-c.done:
		}
	}()

	// Avoid deadlock on JS/WASM environment due to context switch problem.
	time.Sleep(10 * time.Millisecond)

	return &dtlshandshake.WriteResult{}, nil
}

func (c *flightTestConn) HandleQueuedPackets(context.Context) error {
	return nil
}

func (c *flightTestConn) SessionKey() []byte {
	return nil
}

const keyLogEarlyData = "early"

func TestKeyLog(t *testing.T) {
	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	for _, testCase := range []struct {
		name      string
		version   protocol.Version
		suites    []cryptosuite.ID
		scenarios []string
	}{
		{"DTLS12", protocol.Version1_2, []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, []string{"full", "retry"}},
		{"DTLS13", protocol.Version1_3, []cryptosuite.ID{cryptosuite.TLS_AES_128_GCM_SHA256, cryptosuite.TLS_AES_256_GCM_SHA384, cryptosuite.TLS_CHACHA20_POLY1305_SHA256}, []string{"full", "retry", "resumed", keyLogEarlyData}},
	} {
		for _, suite := range testCase.suites {
			for _, scenario := range testCase.scenarios {
				t.Run(fmt.Sprintf("%s/%s/%s", testCase.name, suite, scenario), func(t *testing.T) {
					testKeyLogHandshake(t, certificate, testCase.version, suite, scenario)
				})
			}
		}
	}
}

func testKeyLogHandshake(t *testing.T, certificate tls.Certificate, version protocol.Version, suite cryptosuite.ID, scenario string) {
	t.Helper()
	var clientLog, serverLog bytes.Buffer
	clientOptions := []ClientOption{WithInsecureSkipVerify(true), WithMinVersion(version), WithMaxVersion(version), WithCipherSuites(suite), WithKeyLogWriter(&clientLog)}
	serverOptions := []ServerOption{WithCertificates(certificate), WithMinVersion(version), WithMaxVersion(version), WithCipherSuites(suite), WithKeyLogWriter(&serverLog), WithInsecureSkipVerifyHello(scenario != "retry")}
	if scenario == "resumed" || scenario == keyLogEarlyData {
		secretLen := 32
		if suite == cryptosuite.TLS_AES_256_GCM_SHA384 {
			secretLen = 48
		}
		ticket := Session{Version: 1, IsClient: true, ID: []byte("ticket"), Secret: bytes.Repeat([]byte{0x42}, secretLen), Ticket: &SessionTicket{CipherSuite: suite, CreatedAt: time.Now().Add(-time.Second), Lifetime: 60, MaxEarlyDataSize: 32, PeerCertificates: certificate.Certificate}}
		limit := uint32(0)
		if scenario == keyLogEarlyData {
			limit = 32
		}
		clientOptions = append(clientOptions, WithSessionStore(&earlyDataTestStore{session: ticket}, WithMaxEarlyDataSize(limit)))
		ticket.IsClient = false
		serverOptions = append(serverOptions, WithSessionStore(&earlyDataTestStore{session: ticket}, WithMaxEarlyDataSize(limit)))
	}
	client, err := DetachedClient(&net.UDPAddr{Port: 5555}, clientOptions...)
	require.NoError(t, err)
	server, err := DetachedServer(&net.UDPAddr{Port: 4444}, serverOptions...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, server.Start(ctx))
	require.NoError(t, client.Start(ctx))
	if scenario == keyLogEarlyData {
		_, err = client.WriteEarlyData([]byte(keyLogEarlyData))
		require.NoError(t, err)
	}
	pumpEarlyDataPair(t, client, server)
	require.True(t, client.established.Load())
	require.True(t, server.established.Load())
	assertKeyLog(t, client.conn.state, clientLog.String(), serverLog.String(), scenario)
}

func assertKeyLog(t *testing.T, state dtlsstate.Active, clientLog, serverLog, scenario string) {
	t.Helper()
	var random [32]byte
	var expected map[string][]byte
	var hashSize int
	switch clientState := state.(type) {
	case *dtlsstate.State12:
		random = clientState.LocalRandom.MarshalFixed()
		expected = map[string][]byte{"CLIENT_RANDOM": clientState.MasterSecret}
	case *dtlsstate.State13:
		random = clientState.LocalRandom.MarshalFixed()
		hashSize = clientState.CipherSuite.HashFunc()().Size()
		if scenario == "resumed" || scenario == keyLogEarlyData {
			require.NotEmpty(t, clientState.PSK)
		}
		secrets := clientState.KeySchedule
		expected = map[string][]byte{
			"CLIENT_HANDSHAKE_TRAFFIC_SECRET": secrets.HandshakeTraffic.Client,
			"SERVER_HANDSHAKE_TRAFFIC_SECRET": secrets.HandshakeTraffic.Server,
			"CLIENT_TRAFFIC_SECRET_0":         secrets.ClientApplicationTrafficSecret0,
			"SERVER_TRAFFIC_SECRET_0":         secrets.ServerApplicationTrafficSecret0,
			"EXPORTER_SECRET":                 secrets.ExporterMasterSecret,
		}
	default:
		require.FailNow(t, "unexpected state", "%T", state)
	}
	early := scenario == keyLogEarlyData
	clientLines := strings.Split(strings.TrimSpace(clientLog), "\n")
	serverLines := strings.Split(strings.TrimSpace(serverLog), "\n")
	require.ElementsMatch(t, clientLines, serverLines)
	count := len(expected)
	if early {
		count++
	}
	require.Len(t, clientLines, count)
	for label, secret := range expected {
		require.NotEmpty(t, secret)
		require.Contains(t, clientLines, fmt.Sprintf("%s %x %x", label, random, secret))
	}
	if early {
		require.True(t, strings.HasPrefix(clientLines[0], fmt.Sprintf("CLIENT_EARLY_TRAFFIC_SECRET %x ", random)))
		require.Len(t, strings.Fields(clientLines[0])[2], hashSize*2)
	}
}
