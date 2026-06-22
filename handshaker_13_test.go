// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandshakeFSM13OwnsTranscriptAndPropagatesContext(t *testing.T) {
	state := &State{isClient: true, localVersion: protocol.Version1_3}
	cache := newHandshakeCache()
	cfg := testHandshakeConfig13(t)

	fsm, err := newHandshakeFSM13(state, cache, cfg, flight13_1, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, fsm.transcript)

	flightCtx := fsm.flightContext()
	assert.Same(t, state, flightCtx.state)
	assert.Same(t, cache, flightCtx.cache)
	assert.Same(t, cfg, flightCtx.cfg)
	assert.Same(t, fsm.transcript, flightCtx.transcript)
}

func TestHandshakeFSM13DualStackClientHelloSeedsTranscript(t *testing.T) {
	state := &State{isClient: true, localVersion: protocol.Version1_3}
	cache := newHandshakeCache()
	cfg := testHandshakeConfig13(t)
	cfg.clientHelloMessageHook = func(ch handshake.MessageClientHello) handshake.Message {
		ch.SessionID = []byte{0xaa, 0xbb}

		return &ch
	}

	transcript := newHandshakeTranscript13()
	pkts, dtlsAlert, err := flight13_1Generate(nil, &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	const messageSequence = 7
	content, ok := pkts[0].record.Content.(*handshake.Handshake)
	require.True(t, ok)
	content.Header.MessageSequence = messageSequence

	expected := canonicalPacketHandshake13(t, pkts[0])
	appended, err := appendClientHelloInitialFlights13(transcript, pkts)
	require.NoError(t, err)
	require.True(t, appended)

	fsm, err := newHandshakeFSM13(state, cache, cfg, flight13_1, pkts, transcript)
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
	state := &State{isClient: true, localVersion: protocol.Version1_3}
	cache := newHandshakeCache()
	cfg := testHandshakeConfig13(t)
	transcript := newHandshakeTranscript13()

	pkts, dtlsAlert, err := flight13_1Generate(nil, &handshakeContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)

	fsm, err := newHandshakeFSM13(state, cache, cfg, flight13_1, pkts, transcript)
	require.NoError(t, err)

	transcript = fsm.transcript
	before := append([]byte(nil), transcript.transcript...)
	require.Len(t, transcript.pending, 1)

	fsm.currentFlight = flight13_2
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
	state := &State{isClient: true, localVersion: protocol.Version1_3}
	cache := newHandshakeCache()
	cfg := testHandshakeConfig13(t)

	fsm, err := newHandshakeFSM13(state, cache, cfg, flight13_1, []*packet{}, newHandshakeTranscript13())
	require.Nil(t, fsm)
	require.ErrorIs(t, err, errHandshakeTranscriptMissingClientHello)
}

func canonicalPacketHandshake13(t *testing.T, p *packet) []byte {
	t.Helper()

	content, ok := p.record.Content.(*handshake.Handshake)
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
		localCipherSuites:           cipherSuites,
		ellipticCurves:              defaultCurves,
		initialRetransmitInterval:   time.Second,
		extendedMasterSecret:        RequestExtendedMasterSecret,
		log:                         loggerFactory.NewLogger("dtls"),
		minVersion:                  protocol.Version1_3,
		maxVersion:                  protocol.Version1_3,
		localCertSignatureSchemes:   nil,
		localSRTPProtectionProfiles: nil,
	}
}
