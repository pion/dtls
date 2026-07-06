// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"
	"testing"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCurves13 = []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384} //nolint:gochecknoglobals

type handshakeContext13 struct {
	state      *dtlsstate.State
	cache      *dtlsflight.Cache
	cfg        *dtlsconfig.HandshakeConfig
	transcript *Transcript
}

func (s *fsm13) flightContext() *handshakeContext13 {
	return &handshakeContext13{
		state:      s.state,
		cache:      s.cache,
		cfg:        s.cfg,
		transcript: s.transcript,
	}
}

func flight13GenerateForTest(
	testingT require.TestingT,
	flight dtlsflight13.Flight,
	flightCtx *handshakeContext13,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	if helper, ok := testingT.(interface{ Helper() }); ok {
		helper.Helper()
	}

	gen, _, ok := dtlsflight13.GetGenerator(flight)
	require.True(testingT, ok)

	return gen(nil, flightCtx.state, flightCtx.cache, flightCtx.cfg)
}

type flightTestConn struct {
	localEpoch          uint16
	setLocalEpochCalled bool
	handleQueuedPackets func(context.Context) error
}

func (c *flightTestConn) Notify(context.Context, alert.Level, alert.Description) error {
	return nil
}

func (c *flightTestConn) WritePackets(context.Context, []*dtlsflight.Packet) error {
	return nil
}

func (c *flightTestConn) RecvHandshake() <-chan RecvHandshakeState {
	return nil
}

func (c *flightTestConn) SetLocalEpoch(epoch uint16) {
	c.localEpoch = epoch
	c.setLocalEpochCalled = true
}

func (c *flightTestConn) HandleQueuedPackets(ctx context.Context) error {
	if c.handleQueuedPackets != nil {
		return c.handleQueuedPackets(ctx)
	}

	return nil
}

func (c *flightTestConn) SessionKey() []byte {
	return nil
}

func TestHandshakeFSM13OwnsTranscriptAndPropagatesContext(t *testing.T) {
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)

	fsm, err := newFSM13(state, cache, cfg, dtlsflight13.Flight1, nil, nil)
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

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	const messageSequence = 7
	content, ok := pkts[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	content.Header.MessageSequence = messageSequence

	expected := canonicalPacketHandshake13(t, pkts[0])

	fsm, err := newFSM13(state, cache, cfg, dtlsflight13.Flight1, pkts, nil)
	require.NoError(t, err)
	require.NotNil(t, fsm.transcript)
	require.Len(t, fsm.transcript.pendingMessages(), 1)
	require.Len(t, fsm.transcript.messageOrder(), 1)

	assert.Equal(t, expected, fsm.transcript.pendingMessages()[0])
	assert.Equal(t, expected, fsm.transcript.Bytes())
	assert.Equal(t, transcriptMessageID{
		sender: transcriptSenderClient,
		Seq:    messageSequence,
	}, fsm.transcript.messageOrder()[0].ID)
	assert.Equal(t, handshake.TypeClientHello, fsm.transcript.messageOrder()[0].Type)
}

func TestHandshakeFSM13TranscriptSurvivesStateChangesAndRetransmitSeed(t *testing.T) {
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)

	fsm, err := newFSM13(state, cache, cfg, dtlsflight13.Flight1, pkts, nil)
	require.NoError(t, err)

	transcript := fsm.transcript
	before := append([]byte(nil), transcript.Bytes()...)
	require.Len(t, transcript.pendingMessages(), 1)

	fsm.currentFlight = dtlsflight13.Flight2
	fsm.retransmit = true
	fsm.retransmitInterval *= 2

	assert.Same(t, transcript, fsm.transcript)
	assert.Equal(t, before, fsm.transcript.Bytes())
	assert.Same(t, transcript, fsm.flightContext().transcript)

	require.NoError(t, fsm.seedTranscriptFromInitialFlights())
	assert.Same(t, transcript, fsm.transcript)
	assert.Equal(t, before, fsm.transcript.Bytes())
	assert.Len(t, fsm.transcript.pendingMessages(), 1)
}

func TestHandshakeFSM13DualStackClientHelloRequired(t *testing.T) {
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)

	fsm, err := newFSM13(
		state, cache, cfg, dtlsflight13.Flight1, []*dtlsflight.Packet{}, nil,
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

	fsm, err := newFSM13(state, cache, cfg, dtlsflight13.Flight2, nil, nil)
	require.NoError(t, err)

	nextState, err := fsm.prepare(context.Background(), nil)
	require.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid)
	assert.Equal(t, StateErrored, nextState)
	require.Len(t, fsm.flights, 1)
	assert.Empty(t, fsm.transcript.messageOrder())
	assert.Empty(t, fsm.transcript.Bytes())
	assert.Equal(t, 1, state.HandshakeSendSequence)
}

func TestHandshakeFSM13PrepareCommitsOutboundClientHello(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{IsClient: true, LocalVersion: protocol.Version1_3}
	cache := dtlsflight.NewCache()

	fsm, err := newFSM13(state, cache, cfg, dtlsflight13.Flight1, nil, nil)
	require.NoError(t, err)

	nextState, err := fsm.prepare(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, StateSending, nextState)
	require.Len(t, fsm.flights, 1)

	expected := canonicalPacketHandshake13(t, fsm.flights[0])
	require.Len(t, fsm.transcript.messageOrder(), 1)
	assert.Equal(t, transcriptMessageID{sender: transcriptSenderClient, Seq: 0}, fsm.transcript.messageOrder()[0].ID)
	assert.Equal(t, handshake.TypeClientHello, fsm.transcript.messageOrder()[0].Type)
	assert.Equal(t, expected, fsm.transcript.Bytes())
	assert.Equal(t, 1, state.HandshakeSendSequence)
}

func TestHandshakeFSM13PrepareCommitsOutboundHelloRetryRequestWithSeededTranscript(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{
		LocalVersion: protocol.Version1_3,
		CipherSuite:  cfg.LocalCipherSuites[0],
	}
	cache := dtlsflight.NewCache()
	transcript := NewTranscript()
	clientHello := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello)
	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Packet{clientHello}))

	fsm, err := newFSM13(state, cache, cfg, dtlsflight13.Flight2, nil, transcript)
	require.NoError(t, err)

	nextState, err := fsm.prepare(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, StateSending, nextState)
	require.Len(t, fsm.flights, 1)

	helloRetryRequestCanonical := canonicalPacketHandshake13(t, fsm.flights[0])
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, hashTranscript13(clientHelloCanonical))
	expectedTranscript := append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...)

	assert.Equal(t, expectedTranscript, fsm.transcript.Bytes())
	require.Len(t, fsm.transcript.messageOrder(), 2)
	assert.Equal(t, transcriptMessageID{sender: transcriptSenderServer, Seq: 0}, fsm.transcript.messageOrder()[1].ID)
	assert.Equal(t, handshake.TypeServerHello, fsm.transcript.messageOrder()[1].Type)
	assert.Equal(t, 1, state.HandshakeSendSequence)
}

func TestCommitPreparedFlightsInitializesProtectionBeforeProtectedPackets(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	group := cfg.EllipticCurves[0]
	keypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	state := &dtlsstate.State{
		LocalVersion:    protocol.Version1_3,
		CipherSuite:     cfg.LocalCipherSuites[0],
		LocalKeypair:    keypair,
		LocalRandom:     handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		PreMasterSecret: []byte{0x01, 0x02, 0x03},
	}
	transcript := NewTranscript()
	clientHello := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello)
	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Packet{clientHello}))

	fsm, err := newFSM13(state, dtlsflight.NewCache(), cfg, dtlsflight13.Flight4, nil, transcript)
	require.NoError(t, err)

	conn := &flightTestConn{}
	nextState, err := fsm.prepare(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, StateSending, nextState)
	require.Len(t, fsm.flights, 2)
	assert.Equal(t, dtlsflight13.EpochHandshake, fsm.flights[1].Record.Header.Epoch)
	assert.True(t, fsm.flights[1].ShouldEncrypt)

	serverHelloCanonical := canonicalPacketHandshake13(t, fsm.flights[0])
	encryptedExtensionsCanonical := canonicalPacketHandshake13(t, fsm.flights[1])
	expectedTranscript := append(append(append([]byte(nil), clientHelloCanonical...), serverHelloCanonical...),
		encryptedExtensionsCanonical...)
	assert.Equal(t, expectedTranscript, fsm.transcript.Bytes())
	assert.Equal(t, []transcriptMessage{
		{ID: transcriptMessageID{sender: transcriptSenderClient, Seq: 0}, Type: handshake.TypeClientHello},
		{ID: transcriptMessageID{sender: transcriptSenderServer, Seq: 0}, Type: handshake.TypeServerHello},
		{ID: transcriptMessageID{sender: transcriptSenderServer, Seq: 1}, Type: handshake.TypeEncryptedExtensions},
	}, fsm.transcript.messageOrder())

	expectedSecrets, err := deriveHandshakeTrafficSecrets(
		state.CipherSuite.HashFunc(),
		state.PreMasterSecret,
		hashTranscript13(clientHelloCanonical, serverHelloCanonical),
	)
	require.NoError(t, err)
	assert.Equal(t, expectedSecrets, state.HandshakeTrafficSecrets13)
	assert.True(t, state.CipherSuite.IsInitialized())
	assert.True(t, conn.setLocalEpochCalled)
	assert.Equal(t, dtlsflight13.EpochHandshake, conn.localEpoch)
}

func canonicalPacketHandshake13(t *testing.T, p *dtlsflight.Packet) []byte {
	t.Helper()

	content, ok := p.Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := content.Marshal()
	require.NoError(t, err)
	canonical, err := canonicalHandshake(raw)
	require.NoError(t, err)

	return canonical
}

func testHandshakeConfig13(t *testing.T) *dtlsconfig.HandshakeConfig {
	t.Helper()

	cipherSuite := ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil)
	require.NotNil(t, cipherSuite)

	loggerFactory := logging.NewDefaultLoggerFactory()

	return &dtlsconfig.HandshakeConfig{
		LocalCipherSuites:           []dtlsconfig.CipherSuite{cipherSuite},
		EllipticCurves:              testCurves13,
		InitialRetransmitInterval:   time.Second,
		ExtendedMasterSecret:        dtlsconfig.RequestExtendedMasterSecret,
		Log:                         loggerFactory.NewLogger("dtls"),
		MinVersion:                  protocol.Version1_3,
		MaxVersion:                  protocol.Version1_3,
		LocalSignatureSchemes:       signaturehash.Algorithms13(),
		LocalCertSignatureSchemes:   nil,
		LocalSRTPProtectionProfiles: nil,
	}
}

func TestAppendOutboundHandshakeFlight13ClientHello(t *testing.T) {
	transcript := NewTranscript()
	pkt := transcriptTestClientHelloPacket13([]byte{0x01}, 3)
	expected := canonicalPacketHandshake13(t, pkt)

	err := AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Packet{pkt})
	require.NoError(t, err)
	require.Len(t, transcript.messageOrder(), 1)
	require.Len(t, transcript.pendingMessages(), 1)

	assert.Equal(t, transcriptMessageID{sender: transcriptSenderClient, Seq: 3}, transcript.messageOrder()[0].ID)
	assert.Equal(t, handshake.TypeClientHello, transcript.messageOrder()[0].Type)
	assert.Equal(t, expected, transcript.pendingMessages()[0])
	assert.Equal(t, expected, transcript.Bytes())
}

func TestAppendOutboundHandshakeFlight13DuplicateNoop(t *testing.T) {
	transcript := NewTranscript()
	pkt := transcriptTestClientHelloPacket13([]byte{0x01}, 0)

	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Packet{pkt}))
	before := append([]byte(nil), transcript.Bytes()...)

	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Packet{pkt}))
	assert.Equal(t, before, transcript.Bytes())
	assert.Len(t, transcript.messageOrder(), 1)
}

func TestAppendOutboundHandshakeFlight13ChangedSameSequenceFails(t *testing.T) {
	transcript := NewTranscript()
	pkt := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	changedPkt := transcriptTestClientHelloPacket13([]byte{0x02}, 0)

	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Packet{pkt}))
	err := AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Packet{changedPkt})

	assert.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptMessageChanged)
}

func TestAppendOutboundHandshakeFlight13HelloRetryRequest(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cipherSuite := cfg.LocalCipherSuites[0]
	transcript := NewTranscript()
	clientHello := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	helloRetryRequest := transcriptTestHelloRetryRequestPacket13(t, cipherSuite, 0)

	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello)
	helloRetryRequestCanonical := canonicalPacketHandshake13(t, helloRetryRequest)

	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, cipherSuite, []*dtlsflight.Packet{clientHello}))
	require.NoError(t, AppendOutboundHandshakeFlight(
		transcript, false, cipherSuite, []*dtlsflight.Packet{helloRetryRequest},
	))

	clientHelloHash := hashTranscript13(clientHelloCanonical)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHelloHash)
	expectedTranscript := append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...)
	assert.Equal(t, expectedTranscript, transcript.Bytes())

	sum, err := transcript.sum()
	require.NoError(t, err)
	assert.Equal(t, hashTranscript13(messageHash, helloRetryRequestCanonical), sum)
	require.Len(t, transcript.messageOrder(), 2)
	assert.Equal(t, handshake.TypeClientHello, transcript.messageOrder()[0].Type)
	assert.Equal(t, handshake.TypeServerHello, transcript.messageOrder()[1].Type)

	before := append([]byte(nil), transcript.Bytes()...)
	require.NoError(t, AppendOutboundHandshakeFlight(
		transcript, false, cipherSuite, []*dtlsflight.Packet{helloRetryRequest},
	))
	assert.Equal(t, before, transcript.Bytes())
	assert.Len(t, transcript.messageOrder(), 2)
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
					CipherSuiteIDs:     []uint16{uint16(ciphersuite.TLS_AES_128_GCM_SHA256)},
					CompressionMethods: dtlsflight.DefaultCompressionMethods(),
				},
			},
		},
	}
}

func transcriptTestHelloRetryRequestPacket13(
	tb testing.TB, cipherSuite dtlsconfig.CipherSuite, seq uint16,
) *dtlsflight.Packet {
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
					CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
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
