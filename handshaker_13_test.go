// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"testing"
	"time"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandshakeFSM13OwnsTranscriptAndPropagatesContext(t *testing.T) {
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)

	fsm, err := newHandshakeFSM13(state, cache, cfg, dtlsflight13.Flight1, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, fsm.transcript)

	flightCtx := fsm.flightContext()
	assert.Same(t, state, flightCtx.state)
	assert.Same(t, cache, flightCtx.cache)
	assert.Same(t, cfg, flightCtx.cfg)
	assert.Same(t, fsm.transcript, flightCtx.transcript)
}

func TestHandshakeFSM13DualStackClientHelloSeedsTranscript(t *testing.T) {
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)
	cfg.ClientHelloMessageHook = func(ch handshake.MessageClientHello) handshake.Message {
		ch.SessionID = []byte{0xaa, 0xbb}

		return &ch
	}

	transcript := newHandshakeTranscript13()
	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	const messageSequence = 7
	content, ok := pkts[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	content.Header.MessageSequence = messageSequence

	expected := canonicalPacketHandshake13(t, pkts[0])
	appended, err := appendClientHelloInitialFlights13(transcript, pkts)
	require.NoError(t, err)
	require.True(t, appended)

	fsm, err := newHandshakeFSM13(state, cache, cfg, dtlsflight13.Flight1, pkts, transcript)
	require.NoError(t, err)
	require.NotNil(t, fsm.transcript)
	require.Same(t, transcript, fsm.transcript)
	require.Len(t, fsm.transcript.pending, 1)
	require.Len(t, fsm.transcript.order, 1)

	assert.Equal(t, expected, fsm.transcript.pending[0])
	assert.Equal(t, expected, fsm.transcript.transcript)
	assert.Equal(t, transcriptMessageID13{
		sender: transcriptClient13,
		seq:    messageSequence,
	}, fsm.transcript.order[0].id)
	assert.Equal(t, handshake.TypeClientHello, fsm.transcript.order[0].typ)
}

func TestHandshakeFSM13TranscriptSurvivesStateChangesAndRetransmitSeed(t *testing.T) {
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)
	transcript := newHandshakeTranscript13()

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)

	fsm, err := newHandshakeFSM13(state, cache, cfg, dtlsflight13.Flight1, pkts, transcript)
	require.NoError(t, err)

	transcript = fsm.transcript
	before := append([]byte(nil), transcript.transcript...)
	require.Len(t, transcript.pending, 1)

	fsm.currentFlight = dtlsflight13.Flight2
	fsm.retransmit = true
	fsm.retransmitInterval *= 2

	assert.Same(t, transcript, fsm.transcript)
	assert.Equal(t, before, fsm.transcript.transcript)
	assert.Same(t, transcript, fsm.flightContext().transcript)

	require.NoError(t, fsm.seedTranscriptFromInitialFlights())
	assert.Same(t, transcript, fsm.transcript)
	assert.Equal(t, before, fsm.transcript.transcript)
	assert.Len(t, fsm.transcript.pending, 1)
}

func TestHandshakeFSM13DualStackClientHelloRequired(t *testing.T) {
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)

	fsm, err := newHandshakeFSM13(
		state, cache, cfg, dtlsflight13.Flight1, []*dtlsflight.Packet{}, newHandshakeTranscript13(),
	)
	require.Nil(t, fsm)
	require.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptMissingClientHello)
}

func TestHandshakeFSM13PrepareHelloRetryRequestRequiresSeededTranscript(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{
		LocalVersion: protocol.Version1_3,
		CipherSuite:  cfg.LocalCipherSuites[0],
	}
	cache := dtlsflight.NewCache()

	fsm, err := newHandshakeFSM13(state, cache, cfg, dtlsflight13.Flight2, nil, nil)
	require.NoError(t, err)

	nextState, err := fsm.prepare(context.Background(), nil)
	require.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid)
	assert.Equal(t, handshakeErrored, nextState)
	require.Len(t, fsm.flights, 1)
	assert.Empty(t, fsm.transcript.order)
	assert.Empty(t, fsm.transcript.transcript)
	assert.Equal(t, 1, state.HandshakeSendSequence)
}

func TestHandshakeFSM13PrepareCommitsOutboundClientHello(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()

	fsm, err := newHandshakeFSM13(state, cache, cfg, dtlsflight13.Flight1, nil, nil)
	require.NoError(t, err)

	nextState, err := fsm.prepare(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, handshakeSending, nextState)
	require.Len(t, fsm.flights, 1)

	expected := canonicalPacketHandshake13(t, fsm.flights[0])
	require.Len(t, fsm.transcript.order, 1)
	assert.Equal(t, transcriptMessageID13{sender: transcriptClient13, seq: 0}, fsm.transcript.order[0].id)
	assert.Equal(t, handshake.TypeClientHello, fsm.transcript.order[0].typ)
	assert.Equal(t, expected, fsm.transcript.transcript)
	assert.Equal(t, 1, state.HandshakeSendSequence)
}

func TestHandshakeFSM13PrepareCommitsOutboundHelloRetryRequestWithSeededTranscript(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{
		LocalVersion: protocol.Version1_3,
		CipherSuite:  cfg.LocalCipherSuites[0],
	}
	cache := dtlsflight.NewCache()
	transcript := newHandshakeTranscript13()
	clientHello := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello)
	require.NoError(t, appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{clientHello}))

	fsm, err := newHandshakeFSM13(state, cache, cfg, dtlsflight13.Flight2, nil, transcript)
	require.NoError(t, err)

	nextState, err := fsm.prepare(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, handshakeSending, nextState)
	require.Len(t, fsm.flights, 1)

	helloRetryRequestCanonical := canonicalPacketHandshake13(t, fsm.flights[0])
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, hashTranscript13(clientHelloCanonical))
	expectedTranscript := append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...)

	assert.Equal(t, expectedTranscript, fsm.transcript.transcript)
	require.Len(t, fsm.transcript.order, 2)
	assert.Equal(t, transcriptMessageID13{sender: transcriptServer13, seq: 0}, fsm.transcript.order[1].id)
	assert.Equal(t, handshake.TypeServerHello, fsm.transcript.order[1].typ)
	assert.Equal(t, 1, state.HandshakeSendSequence)
}

func canonicalPacketHandshake13(t *testing.T, p *dtlsflight.Packet) []byte {
	t.Helper()

	content, ok := p.Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := content.Marshal()
	require.NoError(t, err)
	canonical, err := canonicalHandshake13(raw)
	require.NoError(t, err)

	return canonical
}

func testHandshakeConfig13(t *testing.T) *handshakeConfig {
	t.Helper()

	cipherSuites, err := parseCipherSuitesForVersions(
		nil,
		nil,
		true,
		false,
		protocol.Version1_3,
		protocol.Version1_3,
	)
	require.NoError(t, err)

	loggerFactory := logging.NewDefaultLoggerFactory()

	return &handshakeConfig{
		LocalCipherSuites:           cipherSuites,
		EllipticCurves:              defaultCurves,
		InitialRetransmitInterval:   time.Second,
		ExtendedMasterSecret:        dtlsconfig.ExtendedMasterSecretType(RequestExtendedMasterSecret),
		Log:                         loggerFactory.NewLogger("dtls"),
		MinVersion:                  protocol.Version1_3,
		MaxVersion:                  protocol.Version1_3,
		LocalSignatureSchemes:       signaturehash.Algorithms13(),
		LocalCertSignatureSchemes:   nil,
		LocalSRTPProtectionProfiles: nil,
	}
}

func TestAppendOutboundHandshakeFlight13ClientHello(t *testing.T) {
	transcript := newHandshakeTranscript13()
	pkt := transcriptTestClientHelloPacket13([]byte{0x01}, 3)
	expected := canonicalPacketHandshake13(t, pkt)

	err := appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{pkt})
	require.NoError(t, err)
	require.Len(t, transcript.order, 1)
	require.Len(t, transcript.pending, 1)

	assert.Equal(t, transcriptMessageID13{sender: transcriptClient13, seq: 3}, transcript.order[0].id)
	assert.Equal(t, handshake.TypeClientHello, transcript.order[0].typ)
	assert.Equal(t, expected, transcript.pending[0])
	assert.Equal(t, expected, transcript.transcript)
}

func TestAppendOutboundHandshakeFlight13DuplicateNoop(t *testing.T) {
	transcript := newHandshakeTranscript13()
	pkt := transcriptTestClientHelloPacket13([]byte{0x01}, 0)

	require.NoError(t, appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{pkt}))
	before := append([]byte(nil), transcript.transcript...)

	require.NoError(t, appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{pkt}))
	assert.Equal(t, before, transcript.transcript)
	assert.Len(t, transcript.order, 1)
}

func TestAppendOutboundHandshakeFlight13ChangedSameSequenceFails(t *testing.T) {
	transcript := newHandshakeTranscript13()
	pkt := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	changedPkt := transcriptTestClientHelloPacket13([]byte{0x02}, 0)

	require.NoError(t, appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{pkt}))
	err := appendOutboundHandshakeFlight13(transcript, true, nil, []*dtlsflight.Packet{changedPkt})

	assert.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptMessageChanged)
}

func TestAppendOutboundHandshakeFlight13HelloRetryRequest(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cipherSuite := cfg.LocalCipherSuites[0]
	transcript := newHandshakeTranscript13()
	clientHello := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	helloRetryRequest := transcriptTestHelloRetryRequestPacket13(t, cipherSuite, 0)

	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello)
	helloRetryRequestCanonical := canonicalPacketHandshake13(t, helloRetryRequest)

	require.NoError(t, appendOutboundHandshakeFlight13(transcript, true, cipherSuite, []*dtlsflight.Packet{clientHello}))
	require.NoError(t, appendOutboundHandshakeFlight13(
		transcript, false, cipherSuite, []*dtlsflight.Packet{helloRetryRequest},
	))

	clientHelloHash := hashTranscript13(clientHelloCanonical)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHelloHash)
	expectedTranscript := append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...)
	assert.Equal(t, expectedTranscript, transcript.transcript)

	sum, err := transcript.sum()
	require.NoError(t, err)
	assert.Equal(t, hashTranscript13(messageHash, helloRetryRequestCanonical), sum)
	require.Len(t, transcript.order, 2)
	assert.Equal(t, handshake.TypeClientHello, transcript.order[0].typ)
	assert.Equal(t, handshake.TypeServerHello, transcript.order[1].typ)

	before := append([]byte(nil), transcript.transcript...)
	require.NoError(t, appendOutboundHandshakeFlight13(
		transcript, false, cipherSuite, []*dtlsflight.Packet{helloRetryRequest},
	))
	assert.Equal(t, before, transcript.transcript)
	assert.Len(t, transcript.order, 2)
}

func transcriptTestClientHelloPacket13(sessionID []byte, seq uint16) *dtlsflight.Packet {
	return &dtlsflight.Packet{
		Record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				Header: handshake.Header{MessageSequence: seq},
				Message: &handshake.MessageClientHello{
					Version:            protocol.Version1_2,
					SessionID:          sessionID,
					CipherSuiteIDs:     []uint16{uint16(TLS_AES_128_GCM_SHA256)},
					CompressionMethods: defaultCompressionMethods(),
				},
			},
		},
	}
}

func transcriptTestHelloRetryRequestPacket13(tb testing.TB, cipherSuite CipherSuite, seq uint16) *dtlsflight.Packet {
	tb.Helper()

	random := handshake.Random{}
	random.UnmarshalFixed([32]byte(handshake.HelloRetryRequestRandom()))
	cipherSuiteID := uint16(cipherSuite.ID())

	return &dtlsflight.Packet{
		Record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				Header: handshake.Header{MessageSequence: seq},
				Message: &handshake.MessageServerHello{
					Version:           protocol.Version1_2,
					Random:            random,
					CipherSuiteID:     &cipherSuiteID,
					CompressionMethod: defaultCompressionMethods()[0],
					Extensions: []extension.Extension{
						&extension.SupportedVersions{
							Versions:        []protocol.Version{protocol.Version1_3},
							SelectedVersion: true,
						},
					},
				},
			},
		},
	}
}
