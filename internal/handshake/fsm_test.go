// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"
	"crypto"
	"crypto/tls"
	"testing"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlscrypto "github.com/pion/dtls/v3/internal/handshakecrypto"
	"github.com/pion/dtls/v3/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCurves13 = []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384} //nolint:gochecknoglobals

func (s *fsm13) flightContext() *handshakeContext {
	return &s.handshakeContext
}

func flight13GenerateForTest(
	testingT require.TestingT,
	flight dtlsflight13.Flight,
	flightCtx *handshakeContext,
) ([]*dtlsflight.Outbound, *alert.Alert, error) {
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
	writePackets        func(context.Context, []*dtlsflight.Outbound) error
	recvHandshake       chan RecvHandshakeState
	writtenPackets      []*dtlsflight.Outbound
}

func (c *flightTestConn) Notify(context.Context, alert.Level, alert.Description) error {
	return nil
}

func (c *flightTestConn) WritePackets(
	ctx context.Context,
	pkts []*dtlsflight.Outbound,
) (*WriteResult, error) {
	c.writtenPackets = append(c.writtenPackets, pkts...)
	if c.writePackets != nil {
		return nil, c.writePackets(ctx, pkts)
	}

	return &WriteResult{}, nil
}

func (c *flightTestConn) RecvHandshake() <-chan RecvHandshakeState {
	if c.recvHandshake != nil {
		return c.recvHandshake
	}

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

func newTestState13(t *testing.T, isClient bool) *dtlsstate.State13 {
	t.Helper()
	state := dtlsstate.NewState13(isClient)
	_, snapshot, err := negotiation.FinalizeClientHello(&handshake.MessageClientHello{
		CipherSuiteIDs: []uint16{uint16(ciphersuite.TLS_AES_128_GCM_SHA256)},
		Extensions: []extension.Value{
			&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
			&extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(signaturehash.Algorithms())},
			&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519}},
			&extension13.ClientKeyShare{},
		},
	}, nil)
	require.NoError(t, err)
	require.NoError(t, state.RecordLocalClientHello(snapshot))
	require.NoError(t, state.RemoteClientHelloSnapshots.Record(snapshot))

	return &state
}

func TestHandshakeFSMRetransmitTimeout(t *testing.T) {
	tests := []struct {
		name              string
		retransmit        bool
		disableBackoff    bool
		initial, expected time.Duration
		expectedState     State
	}{
		{
			name:          "no retransmit",
			initial:       time.Second,
			expected:      time.Second,
			expectedState: StateWaiting,
		},
		{
			name:          "backoff",
			retransmit:    true,
			initial:       time.Second,
			expected:      2 * time.Second,
			expectedState: StateSending,
		},
		{
			name:           "backoff disabled",
			retransmit:     true,
			disableBackoff: true,
			initial:        time.Second,
			expected:       time.Second,
			expectedState:  StateSending,
		},
		{
			name:          "cap",
			retransmit:    true,
			initial:       45 * time.Second,
			expected:      60 * time.Second,
			expectedState: StateSending,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			interval := test.initial
			cfg := &dtlsconfig.HandshakeConfig{DisableRetransmitBackoff: test.disableBackoff}

			assert.Equal(t, test.expectedState, handleRetransmitTimeout(test.retransmit, &interval, cfg))
			assert.Equal(t, test.expected, interval)
		})
	}
}

func TestHandshakeFSMWaitCancellationResetsRetransmitInterval(t *testing.T) {
	cfg := &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second}
	interval := 30 * time.Second
	errExpected := context.Canceled

	state, err := handleWaitCancellation(&interval, cfg, errExpected)

	assert.Equal(t, StateErrored, state)
	assert.ErrorIs(t, err, errExpected)
	assert.Equal(t, cfg.InitialRetransmitInterval, interval)
}

func TestHandshakeFSM13OwnsTranscriptAndPropagatesContext(t *testing.T) {
	state := newTestState13(t, true)
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

func TestHandshakeFSM13SendACKUsesCurrentEpoch(t *testing.T) {
	state := newTestState13(t, true)
	state.SetLocalEpoch(dtlsflight13.EpochApplication)
	conn := &flightTestConn{}
	fsm := &fsm13{handshakeContext: handshakeContext{state: state}}
	records := []protocol.RecordNumber{{Epoch: 2, SequenceNumber: 7}}

	require.NoError(t, sendACK(context.Background(), conn, fsm.state.LocalEpoch(), records))
	require.Len(t, conn.writtenPackets, 1)
	assert.True(t, conn.writtenPackets[0].Protection == dtlsflight.ProtectionCiphertext)
	assert.Equal(t, dtlsflight13.EpochApplication, conn.writtenPackets[0].Epoch)
	ack, ok := conn.writtenPackets[0].Content.(*protocol.ACK)
	require.True(t, ok)
	assert.Equal(t, records, ack.Records)
}

func TestHandshakeFSM13DoesNotSendEmptyACK(t *testing.T) {
	conn := &flightTestConn{}
	fsm := &fsm13{handshakeContext: handshakeContext{state: newTestState13(t, false)}}

	require.NoError(t, sendACK(context.Background(), conn, fsm.state.LocalEpoch(), nil))
	assert.Empty(t, conn.writtenPackets)
}

func TestHandshakeFSM13ACKProgress(t *testing.T) {
	first := SentHandshakeFragment{MessageSequence: 7, Length: 10}
	second := SentHandshakeFragment{MessageSequence: 7, Offset: 10, Length: 10}
	record1 := protocol.RecordNumber{Epoch: 2, SequenceNumber: 1}
	record2 := protocol.RecordNumber{Epoch: 2, SequenceNumber: 2}
	record3 := protocol.RecordNumber{Epoch: 2, SequenceNumber: 3}

	var ack reliableFlight
	ack.reset()
	ack.track(&WriteResult{TrackedRecords: []SentHandshakeRecord{
		{Number: record1, Fragments: []SentHandshakeFragment{first}},
		{Number: record2, Fragments: []SentHandshakeFragment{second}},
		{Number: record3, Fragments: []SentHandshakeFragment{second}},
	}})

	partial := ack.acknowledge([]protocol.ACK{{Records: []protocol.RecordNumber{record1}}})
	require.Equal(t, []MessageACKProgress{{MessageSequence: 7, Changed: true}}, partial.Messages)
	assert.Equal(t, map[uint32]uint32{10: 10}, ack.pendingForMessage(7))
	assert.Empty(t, ack.acknowledge([]protocol.ACK{{Records: []protocol.RecordNumber{record1}}}).Messages)
	assert.Empty(t, ack.acknowledge(nil).Messages)

	reordered := ack.acknowledge([]protocol.ACK{{Records: []protocol.RecordNumber{record2}}})
	require.Equal(t, []MessageACKProgress{{MessageSequence: 7, Changed: true, Complete: true}}, reordered.Messages)
	assert.Empty(t, ack.pending)
	assert.True(t, ack.acknowledge([]protocol.ACK{{}}).Empty)
}

func TestHandshakeFSM13DualStackClientHelloSeedsTranscript(t *testing.T) {
	state := newTestState13(t, true)
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)
	cfg.ClientHelloMessageHook = func(ch handshake.MessageClientHello) handshake.Message {
		ch.SessionID = []byte{0xaa, 0xbb}

		return &ch
	}

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext{
		state: state,
		cache: cache,
		cfg:   cfg,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	const messageSequence = 7
	content, ok := pkts[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	content.Header.MessageSequence = messageSequence

	expected := canonicalPacketHandshake13(t, pkts[0])

	fsm, err := newFSM13(state, cache, cfg, dtlsflight13.Flight1, pkts, nil)
	require.NoError(t, err)
	require.NotNil(t, fsm.transcript)
	require.Len(t, fsm.transcript.pending, 1)
	require.Len(t, fsm.transcript.order, 1)

	assert.Equal(t, expected, fsm.transcript.pending[0])
	assert.Equal(t, expected, fsm.transcript.Bytes())
	assert.Equal(t, transcriptMessageID{
		sender: transcriptSenderClient,
		Seq:    messageSequence,
	}, fsm.transcript.order[0].ID)
	assert.Equal(t, handshake.TypeClientHello, fsm.transcript.order[0].Type)
}

func TestHandshakeFSM13TranscriptSurvivesStateChangesAndRetransmitSeed(t *testing.T) {
	state := newTestState13(t, true)
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext{
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
	require.Len(t, transcript.pending, 1)

	fsm.currentFlight = dtlsflight13.Flight2
	fsm.retransmit = true
	fsm.retransmitInterval *= 2

	assert.Same(t, transcript, fsm.transcript)
	assert.Equal(t, before, fsm.transcript.Bytes())
	assert.Same(t, transcript, fsm.flightContext().transcript)

	require.NoError(t, fsm.seedInitialFlights(fsm.flights, fsm.retransmit))
	assert.Same(t, transcript, fsm.transcript)
	assert.Equal(t, before, fsm.transcript.Bytes())
	assert.Len(t, fsm.transcript.pending, 1)
}

func TestHandshakeFSM13DualStackClientHelloRequired(t *testing.T) {
	state := newTestState13(t, true)
	cache := dtlsflight.NewCache()
	cfg := testHandshakeConfig13(t)

	fsm, err := newFSM13(
		state, cache, cfg, dtlsflight13.Flight1, []*dtlsflight.Outbound{}, nil,
	)
	require.Nil(t, fsm)
	require.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptMissingClientHello)
}

func TestHandshakeFSM13PrepareHelloRetryRequestRequiresSeededTranscript(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(t, false)
	state.CipherSuite = cfg.LocalCipherSuites[0]
	state.Cookie = []byte{0x01}
	cache := dtlsflight.NewCache()

	fsm, err := newFSM13(state, cache, cfg, dtlsflight13.Flight2, nil, nil)
	require.NoError(t, err)

	nextState, err := fsm.prepare(context.Background(), nil)
	require.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid)
	assert.Equal(t, StateErrored, nextState)
	require.Len(t, fsm.flights, 1)
	assert.Empty(t, fsm.transcript.order)
	assert.Empty(t, fsm.transcript.Bytes())
	assert.Equal(t, 1, state.HandshakeSendSequence)
}

func TestHandshakeFSM13PrepareCommitsOutboundClientHello(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(t, true)
	cache := dtlsflight.NewCache()

	fsm, err := newFSM13(state, cache, cfg, dtlsflight13.Flight1, nil, nil)
	require.NoError(t, err)

	nextState, err := fsm.prepare(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, StateSending, nextState)
	require.Len(t, fsm.flights, 1)

	expected := canonicalPacketHandshake13(t, fsm.flights[0])
	require.Len(t, fsm.transcript.order, 1)
	assert.Equal(t, transcriptMessageID{sender: transcriptSenderClient, Seq: 0}, fsm.transcript.order[0].ID)
	assert.Equal(t, handshake.TypeClientHello, fsm.transcript.order[0].Type)
	assert.Equal(t, expected, fsm.transcript.Bytes())
	assert.Equal(t, 1, state.HandshakeSendSequence)
}

func TestHandshakeFSM13PrepareCommitsOutboundHelloRetryRequestWithSeededTranscript(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(t, false)
	state.CipherSuite = cfg.LocalCipherSuites[0]
	state.Cookie = []byte{0x01}
	cache := dtlsflight.NewCache()
	transcript := NewTranscript()
	clientHello := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello)
	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Outbound{clientHello}))

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
	require.Len(t, fsm.transcript.order, 2)
	assert.Equal(t, transcriptMessageID{sender: transcriptSenderServer, Seq: 0}, fsm.transcript.order[1].ID)
	assert.Equal(t, handshake.TypeServerHello, fsm.transcript.order[1].Type)
	assert.Equal(t, 1, state.HandshakeSendSequence)
}

func TestCommitPreparedFlightsInitializesProtectionBeforeProtectedPackets(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	group := cfg.EllipticCurves[0]
	keypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	state := newTestState13(t, false)
	state.CipherSuite = cfg.LocalCipherSuites[0]
	state.LocalKeypair = keypair
	state.RemoteSignatureSchemes = append([]signaturehash.Algorithm(nil), cfg.LocalSignatureSchemes...)
	state.LocalRandom = handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	state.KeyAgreementSecret = []byte{0x01, 0x02, 0x03}
	transcript := NewTranscript()
	clientHello := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello)
	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Outbound{clientHello}))

	fsm, err := newFSM13(state, dtlsflight.NewCache(), cfg, dtlsflight13.Flight4, nil, transcript)
	require.NoError(t, err)
	transcriptBeforeFlight4, err := transcript.clone()
	require.NoError(t, err)

	conn := &flightTestConn{}
	nextState, err := fsm.prepare(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, StateSending, nextState)
	require.Len(t, fsm.flights, 5)
	for _, pkt := range fsm.flights[1:] {
		assert.Equal(t, dtlsflight13.EpochHandshake, pkt.Epoch)
		assert.True(t, pkt.Protection == dtlsflight.ProtectionCiphertext)
	}

	serverHelloCanonical := canonicalPacketHandshake13(t, fsm.flights[0])
	certificateVerifyTranscript, err := transcriptBeforeFlight4.clone()
	require.NoError(t, err)
	require.NoError(t, AppendOutboundHandshakeFlight(
		certificateVerifyTranscript,
		false,
		state.CipherSuite,
		fsm.flights[:3],
	))
	require.NoError(t, selectHashIfReady(certificateVerifyTranscript, state.CipherSuite))
	serverVerifyInput, err := CertificateVerifyInputFromTranscript(false, certificateVerifyTranscript)
	require.NoError(t, err)
	clientVerifyInput, err := CertificateVerifyInputFromTranscript(true, certificateVerifyTranscript)
	require.NoError(t, err)
	certificateVerifyHandshake := fsm.flights[3].Content.(*handshake.Handshake)                   //nolint:forcetypeassert
	certificateVerify := certificateVerifyHandshake.Message.(*handshake.MessageCertificateVerify) //nolint:forcetypeassert
	require.NoError(t, dtlscrypto.VerifyCertificateVerify(
		serverVerifyInput,
		certificateVerify.HashAlgorithm,
		certificateVerify.SignatureAlgorithm,
		certificateVerify.Signature,
		cfg.LocalCertificates[0].Certificate,
	))
	assert.Error(t, dtlscrypto.VerifyCertificateVerify(
		clientVerifyInput,
		certificateVerify.HashAlgorithm,
		certificateVerify.SignatureAlgorithm,
		certificateVerify.Signature,
		cfg.LocalCertificates[0].Certificate,
	))

	finishedHandshake, ok := fsm.flights[4].Content.(*handshake.Handshake)
	require.True(t, ok)
	finished, ok := finishedHandshake.Message.(*handshake.MessageFinished)
	require.True(t, ok)
	require.Len(t, finished.VerifyData, state.CipherSuite.HashFunc()().Size())

	finishedTranscript, err := transcriptBeforeFlight4.clone()
	require.NoError(t, err)
	require.NoError(t, AppendOutboundHandshakeFlight(
		finishedTranscript,
		false,
		state.CipherSuite,
		fsm.flights[:4],
	))
	require.NoError(t, selectHashIfReady(finishedTranscript, state.CipherSuite))
	baseKey, err := ServerHandshakeFinishedBaseKey(state)
	require.NoError(t, err)
	expectedFinishedVerifyData, err := FinishedVerifyDataFromTranscript(
		state.CipherSuite.HashFunc(),
		baseKey,
		finishedTranscript,
	)
	require.NoError(t, err)
	assert.Equal(t, expectedFinishedVerifyData, finished.VerifyData)

	expectedTranscript := append([]byte(nil), clientHelloCanonical...)
	for _, pkt := range fsm.flights {
		expectedTranscript = append(expectedTranscript, canonicalPacketHandshake13(t, pkt)...)
	}
	assert.Equal(t, expectedTranscript, fsm.transcript.Bytes())
	assert.Equal(t, []transcriptMessage{
		{ID: transcriptMessageID{sender: transcriptSenderClient, Seq: 0}, Type: handshake.TypeClientHello},
		{ID: transcriptMessageID{sender: transcriptSenderServer, Seq: 0}, Type: handshake.TypeServerHello},
		{ID: transcriptMessageID{sender: transcriptSenderServer, Seq: 1}, Type: handshake.TypeEncryptedExtensions},
		{ID: transcriptMessageID{sender: transcriptSenderServer, Seq: 2}, Type: handshake.TypeCertificate},
		{ID: transcriptMessageID{sender: transcriptSenderServer, Seq: 3}, Type: handshake.TypeCertificateVerify},
		{ID: transcriptMessageID{sender: transcriptSenderServer, Seq: 4}, Type: handshake.TypeFinished},
	}, fsm.transcript.order)

	expectedSecrets, err := deriveHandshakeTrafficSecrets(
		state.CipherSuite.HashFunc(),
		state.KeyAgreementSecret,
		hashTranscript13(clientHelloCanonical, serverHelloCanonical),
	)
	require.NoError(t, err)
	assert.Equal(t, expectedSecrets, state.KeySchedule.HandshakeTraffic)
	assert.True(t, state.CipherSuite.IsInitialized())
	assert.True(t, conn.setLocalEpochCalled)
	assert.Equal(t, dtlsflight13.EpochHandshake, conn.localEpoch)
}

func TestHandshakeFSM13SendsFlight4ProtectedRecords(t *testing.T) {
	fixture := newNoHRRFlight13Fixture(t)
	fsm, err := newFSM13(
		fixture.serverState,
		dtlsflight.NewCache(),
		fixture.cfg,
		dtlsflight13.Flight4,
		nil,
		fixture.transcript,
	)
	require.NoError(t, err)

	conn := &flightTestConn{}
	nextState, err := fsm.prepare(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, StateSending, nextState)

	nextState, err = fsm.send(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, StateWaiting, nextState)
	require.Len(t, conn.writtenPackets, 5)

	assert.False(t, conn.writtenPackets[0].Protection == dtlsflight.ProtectionCiphertext)
	assert.Equal(t, dtlsflight13.EpochInitial, conn.writtenPackets[0].Epoch)
	for _, pkt := range conn.writtenPackets[1:] {
		assert.True(t, pkt.Protection == dtlsflight.ProtectionCiphertext)
		assert.Equal(t, dtlsflight13.EpochHandshake, pkt.Epoch)
	}
	assert.True(t, fixture.serverState.CipherSuite.IsInitialized())
	assert.True(t, conn.setLocalEpochCalled)
	assert.Equal(t, dtlsflight13.EpochHandshake, conn.localEpoch)
}

func TestHandshakeFSM13ServerFlight4KeepsReaderPausedThroughQueueDrain(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.InsecureSkipHelloVerify = true
	_, clientHello, _ := newFlight13ClientHelloFixture(t, cfg)
	serverState := newTestState13(t, false)
	cache := dtlsflight.NewCache()
	fsm, err := newFSM13(serverState, cache, cfg, dtlsflight13.Flight0, nil, nil)
	require.NoError(t, err)
	conn := &flightTestConn{recvHandshake: make(chan RecvHandshakeState, 1)}

	nextState, err := fsm.prepare(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, StateSending, nextState)
	nextState, err = fsm.send(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, StateWaiting, nextState)

	pushFlight13HandshakePacketsToCache(t, cache, clientHello, true)
	recvState := RecvHandshakeState{Done: make(chan struct{})}
	conn.recvHandshake <- recvState
	nextState, err = fsm.wait(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, StatePreparing, nextState)
	require.Equal(t, dtlsflight13.Flight4, fsm.currentFlight)
	assertFlight13RecvDoneOpen(t, recvState)

	queueDrains := 0
	conn.writePackets = func(context.Context, []*dtlsflight.Outbound) error {
		assertFlight13RecvDoneOpen(t, recvState)

		return nil
	}
	conn.handleQueuedPackets = func(context.Context) error {
		queueDrains++
		assertFlight13RecvDoneOpen(t, recvState)

		return nil
	}
	nextState, err = fsm.prepare(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, StateSending, nextState)
	assertFlight13RecvDoneOpen(t, recvState)
	nextState, err = fsm.send(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, StateWaiting, nextState)
	assertFlight13RecvDoneClosed(t, recvState)
	assert.Equal(t, 1, queueDrains)
	assert.Equal(t, dtlsflight13.EpochHandshake, serverState.RemoteEpoch())

	conn.writePackets = nil
	nextState, err = fsm.send(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, StateWaiting, nextState)
	assert.Equal(t, 1, queueDrains)
	assert.Equal(t, dtlsflight13.EpochHandshake, serverState.RemoteEpoch())
}

func TestHandshakeFSM13NonDrainingTransitionReleasesReaderAfterWait(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.InsecureSkipHelloVerify = false
	_, clientHello, _ := newFlight13ClientHelloFixture(t, cfg)
	serverState := newTestState13(t, false)
	cache := dtlsflight.NewCache()
	fsm, err := newFSM13(serverState, cache, cfg, dtlsflight13.Flight0, nil, nil)
	require.NoError(t, err)
	conn := &flightTestConn{recvHandshake: make(chan RecvHandshakeState, 1)}

	nextState, err := fsm.prepare(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, StateSending, nextState)
	nextState, err = fsm.send(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, StateWaiting, nextState)

	pushFlight13HandshakePacketsToCache(t, cache, clientHello, true)
	recvState := RecvHandshakeState{Done: make(chan struct{})}
	conn.recvHandshake <- recvState
	nextState, err = fsm.wait(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, StatePreparing, nextState)
	require.Equal(t, dtlsflight13.Flight2, fsm.currentFlight)
	assertFlight13RecvDoneClosed(t, recvState)
}

func TestHandshakeFSM13ReaderPauseRequiredOnlyForQueueDrainingTransitions(t *testing.T) {
	tests := []struct {
		name        string
		isClient    bool
		nextFlight  dtlsflight13.Flight
		remoteEpoch uint16
		expected    bool
	}{
		{
			name:       "client hello retry",
			isClient:   true,
			nextFlight: dtlsflight13.Flight3,
		},
		{
			name:       "client final flight",
			isClient:   true,
			nextFlight: dtlsflight13.Flight5,
			expected:   true,
		},
		{
			name:       "server hello retry",
			nextFlight: dtlsflight13.Flight2,
		},
		{
			name:       "server protected flight",
			nextFlight: dtlsflight13.Flight4,
			expected:   true,
		},
		{
			name:        "server protected flight already activated",
			nextFlight:  dtlsflight13.Flight4,
			remoteEpoch: dtlsflight13.EpochHandshake,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := newTestState13(t, test.isClient)
			state.SetRemoteEpoch(test.remoteEpoch)
			flightContext := handshakeContext{state: state}
			assert.Equal(t, test.expected, flightContext.transitionRequiresReaderPause(test.nextFlight))
		})
	}
}

func TestHandshakeFSM13ServerFlight4RequiresCertificate(t *testing.T) {
	fixture := newNoHRRFlight13Fixture(t)
	fixture.cfg.LocalCertificates = nil
	require.Empty(t, fixture.cfg.LocalCertificates)

	fsm, err := newFSM13(
		fixture.serverState,
		dtlsflight.NewCache(),
		fixture.cfg,
		dtlsflight13.Flight4,
		nil,
		fixture.transcript,
	)
	require.NoError(t, err)

	nextState, err := fsm.prepare(context.Background(), &flightTestConn{})
	require.ErrorIs(t, err, dtlserrors.ErrNoCertificates)
	assert.Equal(t, StateErrored, nextState)
}

func TestHandshakeFSM13WaitParsesProtectedEncryptedExtensions(t *testing.T) {
	fixture := newNoHRRFlight13Fixture(t)
	cache := dtlsflight.NewCache()
	pushFlight13HandshakePacketsToCache(t, cache, fixture.serverFlight4, false)

	fsm, err := newFSM13(
		fixture.clientState,
		cache,
		fixture.cfg,
		dtlsflight13.Flight3,
		nil,
		fixture.transcript,
	)
	require.NoError(t, err)

	conn := &flightTestConn{recvHandshake: make(chan RecvHandshakeState, 1)}
	recvState := RecvHandshakeState{Done: make(chan struct{})}
	conn.recvHandshake <- recvState

	nextState, err := fsm.wait(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, StatePreparing, nextState)
	assert.Equal(t, dtlsflight13.Flight5, fsm.currentFlight)
	assert.Equal(t, 5, fixture.clientState.HandshakeRecvSequence)
	assert.True(t, fixture.clientState.CipherSuite.IsInitialized())
	assert.Equal(t, dtlsflight13.EpochHandshake, fixture.clientState.RemoteEpoch())
	assertFlight13RecvDoneOpen(t, recvState)
	assertFlight13ClientTranscriptThroughServerFinished(t, fsm.transcript)

	conn.writePackets = func(context.Context, []*dtlsflight.Outbound) error {
		assertFlight13RecvDoneOpen(t, recvState)

		return nil
	}
	conn.handleQueuedPackets = func(context.Context) error {
		assertFlight13RecvDoneOpen(t, recvState)

		return nil
	}
	nextState, err = fsm.prepare(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, StateSending, nextState)
	assertFlight13RecvDoneOpen(t, recvState)
	nextState, err = fsm.send(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, StateFinished, nextState)
	assertFlight13RecvDoneClosed(t, recvState)
}

func TestHandshakeFSM13PartialProtectedServerFlightACKUsesHandshakeEpoch(t *testing.T) {
	fixture := newNoHRRFlight13Fixture(t)
	cache := dtlsflight.NewCache()
	fsm, err := newFSM13(
		fixture.clientState,
		cache,
		fixture.cfg,
		dtlsflight13.Flight3,
		nil,
		fixture.transcript,
	)
	require.NoError(t, err)
	conn := &flightTestConn{}

	pushFlight13HandshakePacketsToCache(t, cache, fixture.serverFlight4[:1], false)
	first := RecvHandshakeState{Done: make(chan struct{}), HasHandshake: true}
	transition, err := fsm.handleReceivedFlight(context.Background(), conn, first)
	require.NoError(t, err)
	assert.Equal(t, StateWaiting, transition.state)
	fsm.received.release()
	assertFlight13RecvDoneClosed(t, first)

	pushFlight13HandshakePacketsToCache(t, cache, fixture.serverFlight4[1:2], false)
	record := protocol.RecordNumber{Epoch: uint64(dtlsflight13.EpochHandshake), SequenceNumber: 7}
	second := RecvHandshakeState{
		Done:         make(chan struct{}),
		HasHandshake: true,
		RecordsToACK: []protocol.RecordNumber{record},
	}
	transition, err = fsm.handleReceivedFlight(context.Background(), conn, second)
	require.NoError(t, err)
	assert.Equal(t, StateWaiting, transition.state)
	require.Len(t, conn.writtenPackets, 1)
	ackPacket := conn.writtenPackets[0]
	assert.True(t, ackPacket.Protection == dtlsflight.ProtectionCiphertext)
	assert.Equal(t, dtlsflight13.EpochHandshake, ackPacket.Epoch)
	ack, ok := ackPacket.Content.(*protocol.ACK)
	require.True(t, ok)
	assert.Equal(t, []protocol.RecordNumber{record}, ack.Records)
	fsm.received.release()
	assertFlight13RecvDoneClosed(t, second)
}

func TestHandshakeFSM13NoHRRReachesFlight5AfterEncryptedExtensions(t *testing.T) {
	fixture := newNoHRRFlight13Fixture(t)
	cache := dtlsflight.NewCache()
	pushFlight13HandshakePacketsToCache(t, cache, fixture.serverFlight4, false)

	fsm, err := newFSM13(
		fixture.clientState,
		cache,
		fixture.cfg,
		dtlsflight13.Flight1,
		fixture.clientHello,
		nil,
	)
	require.NoError(t, err)

	conn := &flightTestConn{recvHandshake: make(chan RecvHandshakeState, 1)}
	recvState := RecvHandshakeState{Done: make(chan struct{})}
	conn.recvHandshake <- recvState

	nextState, err := fsm.wait(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, StatePreparing, nextState)
	assert.Equal(t, dtlsflight13.Flight5, fsm.currentFlight)
	assert.Equal(t, 5, fixture.clientState.HandshakeRecvSequence)
	assertFlight13RecvDoneOpen(t, recvState)
	assertFlight13ClientTranscriptThroughServerFinished(t, fsm.transcript)
	fsm.received.release()
	assertFlight13RecvDoneClosed(t, recvState)
}

func TestHandshakeFSM13NoHRRSplitServerFlightAcrossReceives(t *testing.T) {
	fixture := newNoHRRFlight13Fixture(t)
	cache := dtlsflight.NewCache()
	fsm, err := newFSM13(
		fixture.clientState,
		cache,
		fixture.cfg,
		dtlsflight13.Flight1,
		fixture.clientHello,
		nil,
	)
	require.NoError(t, err)
	conn := &flightTestConn{}

	pushFlight13HandshakePacketsToCache(t, cache, fixture.serverFlight4[:1], false)
	first := RecvHandshakeState{Done: make(chan struct{}), HasHandshake: true}
	transition, err := fsm.handleReceivedFlight(context.Background(), conn, first)
	require.NoError(t, err)
	assert.Equal(t, StateWaiting, transition.state)
	assert.Equal(t, 1, fixture.clientState.HandshakeRecvSequence)
	assert.Equal(t, dtlsflight13.EpochHandshake, fixture.clientState.RemoteEpoch())
	fsm.received.release()
	assertFlight13RecvDoneClosed(t, first)

	pushFlight13HandshakePacketsToCache(t, cache, fixture.serverFlight4[1:], false)
	second := RecvHandshakeState{Done: make(chan struct{}), HasHandshake: true}
	transition, err = fsm.handleReceivedFlight(context.Background(), conn, second)
	require.NoError(t, err)
	assert.Equal(t, StatePreparing, transition.state)
	assert.Equal(t, dtlsflight13.Flight5, fsm.currentFlight)
	assert.Equal(t, 5, fixture.clientState.HandshakeRecvSequence)
	fsm.received.release()
	assertFlight13RecvDoneClosed(t, second)
}

func TestHandshakeFSM13ClientFlight5GeneratesFinished(t *testing.T) {
	fixture := newNoHRRFlight13Fixture(t)
	fsm := clientFSMThroughServerFlight13(t, fixture)
	transcriptThroughServerFinished, err := fsm.transcript.clone()
	require.NoError(t, err)

	conn := &flightTestConn{}
	nextState, err := fsm.prepare(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, StateSending, nextState)
	require.Len(t, fsm.flights, 1)

	pkt := fsm.flights[0]
	assert.True(t, pkt.Protection == dtlsflight.ProtectionCiphertext)
	assert.Equal(t, dtlsflight13.EpochHandshake, pkt.Epoch)

	finishedHandshake, ok := pkt.Content.(*handshake.Handshake)
	require.True(t, ok)
	assert.Equal(t, uint16(1), finishedHandshake.Header.MessageSequence)
	finished, ok := finishedHandshake.Message.(*handshake.MessageFinished)
	require.True(t, ok)

	baseKey, err := ClientHandshakeFinishedBaseKey(fixture.clientState)
	require.NoError(t, err)
	expectedVerifyData, err := FinishedVerifyDataFromTranscript(
		fixture.clientState.CipherSuite.HashFunc(),
		baseKey,
		transcriptThroughServerFinished,
	)
	require.NoError(t, err)
	assert.Equal(t, expectedVerifyData, finished.VerifyData)

	expectedTranscript, err := transcriptThroughServerFinished.clone()
	require.NoError(t, err)
	require.NoError(t, AppendOutboundHandshakeFlight(
		expectedTranscript,
		true,
		fixture.clientState.CipherSuite,
		fsm.flights,
	))
	assert.Equal(t, expectedTranscript.Bytes(), fsm.transcript.Bytes())
	assert.Equal(t, transcriptMessage{
		ID:   transcriptMessageID{sender: transcriptSenderClient, Seq: 1},
		Type: handshake.TypeFinished,
	}, fsm.transcript.order[6])
	assert.True(t, conn.setLocalEpochCalled)
	assert.Equal(t, dtlsflight13.EpochHandshake, conn.localEpoch)
}

func TestHandshakeFSM13ClientFlight5HandlesPreviousFlightRetransmit(t *testing.T) {
	fixture := newNoHRRFlight13Fixture(t)
	fsm := clientFSMThroughServerFlight13(t, fixture)
	conn := &flightTestConn{}
	nextState, err := fsm.prepare(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, StateSending, nextState)
	require.Equal(t, dtlsflight13.Flight5, fsm.currentFlight)

	fixture.clientState.SetLocalEpoch(dtlsflight13.EpochHandshake)
	record := protocol.RecordNumber{Epoch: uint64(dtlsflight13.EpochHandshake), SequenceNumber: 11}
	retransmit := RecvHandshakeState{
		Done:         make(chan struct{}),
		HasHandshake: true,
		IsRetransmit: true,
		RecordsToACK: []protocol.RecordNumber{record},
	}
	transition, err := fsm.handleReceivedFlight(context.Background(), conn, retransmit)
	require.NoError(t, err)
	assert.Equal(t, StateSending, transition.state)
	assert.Equal(t, dtlsflight13.Flight5, fsm.currentFlight)
	require.Len(t, conn.writtenPackets, 1)
	ackPacket := conn.writtenPackets[0]
	assert.True(t, ackPacket.Protection == dtlsflight.ProtectionCiphertext)
	assert.Equal(t, dtlsflight13.EpochHandshake, ackPacket.Epoch)
	ack, ok := ackPacket.Content.(*protocol.ACK)
	require.True(t, ok)
	assert.Equal(t, []protocol.RecordNumber{record}, ack.Records)
	fsm.received.release()
	assertFlight13RecvDoneClosed(t, retransmit)
}

func TestHandshakeFSM13SendErrorReleasesReader(t *testing.T) {
	tests := []struct {
		name     string
		writeErr error
		queueErr error
	}{
		{name: "write", writeErr: context.Canceled},
		{name: "queue drain", queueErr: context.Canceled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fsm := clientFSMThroughServerFlight13(t, newNoHRRFlight13Fixture(t))
			recvState := RecvHandshakeState{Done: fsm.received.done}
			conn := &flightTestConn{
				writePackets: func(context.Context, []*dtlsflight.Outbound) error {
					assertFlight13RecvDoneOpen(t, recvState)

					return test.writeErr
				},
				handleQueuedPackets: func(context.Context) error {
					assertFlight13RecvDoneOpen(t, recvState)

					return test.queueErr
				},
			}

			nextState, err := fsm.prepare(context.Background(), conn)
			require.NoError(t, err)
			require.Equal(t, StateSending, nextState)
			assertFlight13RecvDoneOpen(t, recvState)
			nextState, err = fsm.send(context.Background(), conn)
			require.ErrorIs(t, err, context.Canceled)
			assert.Equal(t, StateErrored, nextState)
			assertFlight13RecvDoneClosed(t, recvState)
		})
	}
}

func TestHandshakeFSM13ClientFlight5WithCertificate(t *testing.T) {
	fixture := addCertificateRequestToServerFlight13(
		t,
		newNoHRRFlight13Fixture(t),
		[]byte{0x01, 0x02, 0x03},
	)
	clientCertificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	fixture.cfg.LocalCertificates = []tls.Certificate{clientCertificate}

	fsm := clientFSMThroughServerFlight13(t, fixture)
	transcriptThroughServerFinished, err := fsm.transcript.clone()
	require.NoError(t, err)

	nextState, err := fsm.prepare(context.Background(), &flightTestConn{})
	require.NoError(t, err)
	assert.Equal(t, StateSending, nextState)
	require.Len(t, fsm.flights, 3)

	expectedTypes := []handshake.Type{
		handshake.TypeCertificate,
		handshake.TypeCertificateVerify,
		handshake.TypeFinished,
	}
	for i, pkt := range fsm.flights {
		assert.True(t, pkt.Protection == dtlsflight.ProtectionCiphertext)
		assert.Equal(t, dtlsflight13.EpochHandshake, pkt.Epoch)

		hs, ok := pkt.Content.(*handshake.Handshake)
		require.True(t, ok)
		assert.Equal(t, expectedTypes[i], hs.Message.Type())
		assert.Equal(t, uint16(i+1), hs.Header.MessageSequence)
	}

	certificateHandshake := fsm.flights[0].Content.(*handshake.Handshake)         //nolint:forcetypeassert
	certificate := certificateHandshake.Message.(*handshake.MessageCertificate13) //nolint:forcetypeassert
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, certificate.CertificateRequestContext)
	require.Len(t, certificate.CertificateList, len(clientCertificate.Certificate))
	for i, entry := range certificate.CertificateList {
		assert.Equal(t, clientCertificate.Certificate[i], entry.CertificateData)
	}

	expectedTranscript, err := transcriptThroughServerFinished.clone()
	require.NoError(t, err)
	require.NoError(t, AppendOutboundHandshakeFlight(
		expectedTranscript,
		true,
		fixture.clientState.CipherSuite,
		fsm.flights[:1],
	))
	certificateVerifyInput, err := CertificateVerifyInputFromTranscript(true, expectedTranscript)
	require.NoError(t, err)

	certificateVerifyHandshake := fsm.flights[1].Content.(*handshake.Handshake)                   //nolint:forcetypeassert
	certificateVerify := certificateVerifyHandshake.Message.(*handshake.MessageCertificateVerify) //nolint:forcetypeassert
	require.NotEmpty(t, certificateVerify.Signature)
	require.NoError(t, dtlscrypto.VerifyCertificateVerify(
		certificateVerifyInput,
		certificateVerify.HashAlgorithm,
		certificateVerify.SignatureAlgorithm,
		certificateVerify.Signature,
		clientCertificate.Certificate,
	))

	require.NoError(t, AppendOutboundHandshakeFlight(
		expectedTranscript,
		true,
		fixture.clientState.CipherSuite,
		fsm.flights[1:2],
	))
	baseKey, err := ClientHandshakeFinishedBaseKey(fixture.clientState)
	require.NoError(t, err)
	expectedVerifyData, err := FinishedVerifyDataFromTranscript(
		fixture.clientState.CipherSuite.HashFunc(),
		baseKey,
		expectedTranscript,
	)
	require.NoError(t, err)

	finishedHandshake := fsm.flights[2].Content.(*handshake.Handshake) //nolint:forcetypeassert
	finished := finishedHandshake.Message.(*handshake.MessageFinished) //nolint:forcetypeassert
	assert.Equal(t, expectedVerifyData, finished.VerifyData)

	require.NoError(t, AppendOutboundHandshakeFlight(
		expectedTranscript,
		true,
		fixture.clientState.CipherSuite,
		fsm.flights[2:],
	))
	assert.Equal(t, expectedTranscript.Bytes(), fsm.transcript.Bytes())
	assert.Equal(t, []transcriptMessage{
		{ID: transcriptMessageID{sender: transcriptSenderClient, Seq: 1}, Type: handshake.TypeCertificate},
		{ID: transcriptMessageID{sender: transcriptSenderClient, Seq: 2}, Type: handshake.TypeCertificateVerify},
		{ID: transcriptMessageID{sender: transcriptSenderClient, Seq: 3}, Type: handshake.TypeFinished},
	}, fsm.transcript.order[7:])
}

func TestHandshakeFSM13ClientFlight5WithoutClientCertificate(t *testing.T) {
	clientCertificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	tests := map[string]struct {
		makeFixture   func(*testing.T) noHRRFlight13Fixture
		expectedTypes []handshake.Type
	}{
		"certificate request absent": {
			makeFixture: func(t *testing.T) noHRRFlight13Fixture {
				t.Helper()
				fixture := newNoHRRFlight13Fixture(t)
				fixture.cfg.LocalCertificates = []tls.Certificate{clientCertificate}

				return fixture
			},
			expectedTypes: []handshake.Type{handshake.TypeFinished},
		},
		"optional certificate request without credentials": {
			makeFixture: func(t *testing.T) noHRRFlight13Fixture {
				t.Helper()
				fixture := addCertificateRequestToServerFlight13(t, newNoHRRFlight13Fixture(t), nil)
				fixture.cfg.LocalCertificates = nil

				return fixture
			},
			expectedTypes: []handshake.Type{handshake.TypeCertificate, handshake.TypeFinished},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fsm := clientFSMThroughServerFlight13(t, test.makeFixture(t))
			transcriptThroughServerFinished, err := fsm.transcript.clone()
			require.NoError(t, err)

			nextState, err := fsm.prepare(context.Background(), &flightTestConn{})
			require.NoError(t, err)
			assert.Equal(t, StateSending, nextState)
			require.Len(t, fsm.flights, len(test.expectedTypes))

			for i, expectedType := range test.expectedTypes {
				hs, ok := fsm.flights[i].Content.(*handshake.Handshake)
				require.True(t, ok)
				assert.Equal(t, expectedType, hs.Message.Type())
			}

			if test.expectedTypes[0] == handshake.TypeCertificate {
				hs := fsm.flights[0].Content.(*handshake.Handshake)         //nolint:forcetypeassert
				certificate := hs.Message.(*handshake.MessageCertificate13) //nolint:forcetypeassert
				assert.Empty(t, certificate.CertificateRequestContext)
				assert.Empty(t, certificate.CertificateList)
				assert.Equal(t, []transcriptMessage{
					{ID: transcriptMessageID{sender: transcriptSenderClient, Seq: 1}, Type: handshake.TypeCertificate},
					{ID: transcriptMessageID{sender: transcriptSenderClient, Seq: 2}, Type: handshake.TypeFinished},
				}, fsm.transcript.order[7:])

				require.NoError(t, AppendOutboundHandshakeFlight(
					transcriptThroughServerFinished,
					true,
					fsm.state.CipherSuite,
					fsm.flights[:1],
				))
				baseKey, err := ClientHandshakeFinishedBaseKey(fsm.state)
				require.NoError(t, err)
				expectedVerifyData, err := FinishedVerifyDataFromTranscript(
					fsm.state.CipherSuite.HashFunc(),
					baseKey,
					transcriptThroughServerFinished,
				)
				require.NoError(t, err)
				finishedHandshake := fsm.flights[1].Content.(*handshake.Handshake) //nolint:forcetypeassert
				finished := finishedHandshake.Message.(*handshake.MessageFinished) //nolint:forcetypeassert
				assert.Equal(t, expectedVerifyData, finished.VerifyData)
			}
		})
	}
}

func TestHandshakeFSM13ServerVerifiesClientFinishedAndCompletes(t *testing.T) {
	fixture := newNoHRRFlight13Fixture(t)
	clientFSM := clientFSMThroughServerFlight13(t, fixture)
	nextState, err := clientFSM.prepare(context.Background(), &flightTestConn{})
	require.NoError(t, err)
	require.Equal(t, StateSending, nextState)

	serverFSM := serverFSMForClientFlight13(t, fixture, clientFSM.flights, 1)
	conn := &flightTestConn{recvHandshake: make(chan RecvHandshakeState, 1)}
	recvState := RecvHandshakeState{Done: make(chan struct{})}
	conn.handleQueuedPackets = func(context.Context) error {
		assertFlight13RecvDoneOpen(t, recvState)

		return nil
	}
	conn.recvHandshake <- recvState

	nextState, err = serverFSM.wait(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, StateFinished, nextState)
	assert.Equal(t, 2, fixture.serverState.HandshakeRecvSequence)
	assert.Equal(t, dtlsflight13.EpochApplication, fixture.serverState.RemoteEpoch())
	assert.True(t, conn.setLocalEpochCalled)
	assert.Equal(t, dtlsflight13.EpochApplication, conn.localEpoch)
	assertFlight13RecvDoneClosed(t, recvState)
	assert.Equal(t, transcriptMessage{
		ID:   transcriptMessageID{sender: transcriptSenderClient, Seq: 1},
		Type: handshake.TypeFinished,
	}, serverFSM.transcript.order[6])
}

func TestHandshakeFSM13ServerRejectsTamperedClientFinished(t *testing.T) {
	fixture := newNoHRRFlight13Fixture(t)
	clientFSM := clientFSMThroughServerFlight13(t, fixture)
	nextState, err := clientFSM.prepare(context.Background(), &flightTestConn{})
	require.NoError(t, err)
	require.Equal(t, StateSending, nextState)
	require.Len(t, clientFSM.flights, 1)

	finishedHandshake := clientFSM.flights[0].Content.(*handshake.Handshake) //nolint:forcetypeassert
	rawFinished, err := finishedHandshake.Marshal()
	require.NoError(t, err)
	rawFinished[len(rawFinished)-1] ^= 0xff

	serverTranscript := serverTranscriptThroughFlight4(t, fixture)
	transcriptBefore := append([]byte(nil), serverTranscript.Bytes()...)
	cache := dtlsflight.NewCache()
	cache.Push(
		rawFinished,
		dtlsflight13.EpochHandshake,
		finishedHandshake.Header.MessageSequence,
		handshake.TypeFinished,
		true,
	)
	serverFSM, err := newFSM13(
		fixture.serverState,
		cache,
		fixture.cfg,
		dtlsflight13.Flight4,
		nil,
		serverTranscript,
	)
	require.NoError(t, err)
	conn := &flightTestConn{recvHandshake: make(chan RecvHandshakeState, 1)}
	recvState := RecvHandshakeState{Done: make(chan struct{})}
	conn.recvHandshake <- recvState

	nextState, err = serverFSM.wait(context.Background(), conn)
	require.ErrorIs(t, err, dtlserrors.ErrVerifyDataMismatch)
	assert.Equal(t, StateErrored, nextState)
	assert.Equal(t, transcriptBefore, serverFSM.transcript.Bytes())
	assert.Equal(t, 1, fixture.serverState.HandshakeRecvSequence)
	assertFlight13RecvDoneClosed(t, recvState)
}

func TestHandshakeFSM13ServerVerifiesClientCertificateVerify(t *testing.T) {
	fixture := addCertificateRequestToServerFlight13(
		t,
		newNoHRRFlight13Fixture(t),
		[]byte{0x01, 0x02, 0x03},
	)
	clientCertificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	fixture.cfg.LocalCertificates = []tls.Certificate{clientCertificate}
	fixture.cfg.ClientAuth = dtlsconfig.RequestClientCert

	clientFSM := clientFSMThroughServerFlight13(t, fixture)
	nextState, err := clientFSM.prepare(context.Background(), &flightTestConn{})
	require.NoError(t, err)
	require.Equal(t, StateSending, nextState)
	require.Len(t, clientFSM.flights, 3)

	serverFSM := serverFSMForClientFlight13(t, fixture, clientFSM.flights, 1)
	conn := &flightTestConn{recvHandshake: make(chan RecvHandshakeState, 1)}
	recvState := RecvHandshakeState{Done: make(chan struct{})}
	conn.recvHandshake <- recvState

	nextState, err = serverFSM.wait(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, StateFinished, nextState)
	assert.Equal(t, clientCertificate.Certificate, fixture.serverState.PeerCertificates)
	assert.Equal(t, 4, fixture.serverState.HandshakeRecvSequence)
	assertFlight13RecvDoneClosed(t, recvState)
}

func TestHandshakeFSM13RetransmittedFinalFlightDoesNotChangeTranscript(t *testing.T) {
	fixture := newNoHRRFlight13Fixture(t)
	clientFSM := clientFSMThroughServerFlight13(t, fixture)
	nextState, err := clientFSM.prepare(context.Background(), &flightTestConn{})
	require.NoError(t, err)
	require.Equal(t, StateSending, nextState)

	serverFSM := serverFSMForClientFlight13(t, fixture, clientFSM.flights, 2)
	conn := &flightTestConn{recvHandshake: make(chan RecvHandshakeState, 2)}
	first := RecvHandshakeState{Done: make(chan struct{})}
	conn.recvHandshake <- first
	nextState, err = serverFSM.wait(context.Background(), conn)
	require.NoError(t, err)
	require.Equal(t, StateFinished, nextState)
	assertFlight13RecvDoneClosed(t, first)

	transcriptBefore := append([]byte(nil), serverFSM.transcript.Bytes()...)
	orderBefore := append([]transcriptMessage(nil), serverFSM.transcript.order...)
	retransmit := RecvHandshakeState{Done: make(chan struct{}), IsRetransmit: true}
	conn.recvHandshake <- retransmit
	nextState, err = serverFSM.finish(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, StateFinished, nextState)
	assertFlight13RecvDoneClosed(t, retransmit)
	assert.Equal(t, transcriptBefore, serverFSM.transcript.Bytes())
	assert.Equal(t, orderBefore, serverFSM.transcript.order)
}

func serverFSMForClientFlight13(
	t *testing.T,
	fixture noHRRFlight13Fixture,
	clientFlight []*dtlsflight.Outbound,
	cacheCopies int,
) *fsm13 {
	t.Helper()

	transcript := serverTranscriptThroughFlight4(t, fixture)
	cache := dtlsflight.NewCache()
	for range cacheCopies {
		pushFlight13HandshakePacketsToCache(t, cache, clientFlight, true)
	}
	fsm, err := newFSM13(
		fixture.serverState,
		cache,
		fixture.cfg,
		dtlsflight13.Flight4,
		nil,
		transcript,
	)
	require.NoError(t, err)

	return fsm
}

func serverTranscriptThroughFlight4(t *testing.T, fixture noHRRFlight13Fixture) *Transcript {
	t.Helper()

	transcript := NewTranscript()
	require.NoError(t, AppendOutboundHandshakeFlight(
		transcript,
		true,
		fixture.serverState.CipherSuite,
		fixture.clientHello,
	))
	require.NoError(t, AppendOutboundHandshakeFlight(
		transcript,
		false,
		fixture.serverState.CipherSuite,
		fixture.serverFlight4,
	))
	require.NoError(t, DeriveAndStoreApplicationTrafficSecrets(fixture.serverState, transcript))

	return transcript
}

func canonicalPacketHandshake13(t *testing.T, p *dtlsflight.Outbound) []byte {
	t.Helper()

	content, ok := p.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := content.Marshal()
	require.NoError(t, err)
	canonical, err := canonicalHandshake(raw)
	require.NoError(t, err)

	return canonical
}

func clientFSMThroughServerFlight13(t *testing.T, fixture noHRRFlight13Fixture) *fsm13 {
	t.Helper()

	cache := dtlsflight.NewCache()
	pushFlight13HandshakePacketsToCache(t, cache, fixture.serverFlight4, false)
	fsm, err := newFSM13(
		fixture.clientState,
		cache,
		fixture.cfg,
		dtlsflight13.Flight3,
		nil,
		fixture.transcript,
	)
	require.NoError(t, err)

	conn := &flightTestConn{recvHandshake: make(chan RecvHandshakeState, 1)}
	recvState := RecvHandshakeState{Done: make(chan struct{})}
	conn.recvHandshake <- recvState
	nextState, err := fsm.wait(context.Background(), conn)
	require.NoError(t, err)
	assert.Equal(t, StatePreparing, nextState)
	assert.Equal(t, dtlsflight13.Flight5, fsm.currentFlight)
	assertFlight13RecvDoneOpen(t, recvState)
	t.Cleanup(fsm.received.release)

	return fsm
}

func addCertificateRequestToServerFlight13(
	t *testing.T,
	fixture noHRRFlight13Fixture,
	requestContext []byte,
) noHRRFlight13Fixture {
	t.Helper()

	request := &dtlsflight.Outbound{
		Epoch: dtlsflight13.EpochHandshake,
		Content: &handshake.Handshake{
			Header: handshake.Header{MessageSequence: 2},
			Message: &handshake.MessageCertificateRequest13{
				CertificateRequestContext: requestContext,
				Extensions: []extension.Value{
					&extension.SignatureAlgorithms{
						Schemes: dtlsflight.SignatureSchemeIDs(fixture.cfg.LocalSignatureSchemes),
					},
				},
			},
		},
		Protection: dtlsflight.ProtectionCiphertext,
	}

	fixture.serverFlight4 = []*dtlsflight.Outbound{
		fixture.serverFlight4[0],
		fixture.serverFlight4[1],
		request,
		fixture.serverFlight4[2],
		fixture.serverFlight4[3],
		fixture.serverFlight4[4],
	}
	for i, pkt := range fixture.serverFlight4 {
		setFlight13HandshakeSequence(t, pkt, uint16(i))
	}

	certificateVerifyHandshake := fixture.serverFlight4[4].Content.(*handshake.Handshake)         //nolint:forcetypeassert
	certificateVerify := certificateVerifyHandshake.Message.(*handshake.MessageCertificateVerify) //nolint:forcetypeassert
	signer, ok := fixture.cfg.LocalCertificates[0].PrivateKey.(crypto.Signer)
	require.True(t, ok)
	certificateVerify.Signature = nil

	certificateVerifyTranscript, err := fixture.transcript.clone()
	require.NoError(t, err)
	require.NoError(t, selectHashIfReady(certificateVerifyTranscript, fixture.serverState.CipherSuite))
	require.NoError(t, AppendOutboundHandshakeFlight(
		certificateVerifyTranscript,
		false,
		fixture.serverState.CipherSuite,
		fixture.serverFlight4[:4],
	))
	verifyInput, err := CertificateVerifyInputFromTranscript(false, certificateVerifyTranscript)
	require.NoError(t, err)
	certificateVerify.Signature, err = dtlscrypto.GenerateCertificateVerify(
		verifyInput,
		signer,
		certificateVerify.HashAlgorithm,
		certificateVerify.SignatureAlgorithm,
	)
	require.NoError(t, err)

	finishedHandshake := fixture.serverFlight4[5].Content.(*handshake.Handshake) //nolint:forcetypeassert
	finished := finishedHandshake.Message.(*handshake.MessageFinished)           //nolint:forcetypeassert
	finished.VerifyData = nil

	serverTranscript, err := fixture.transcript.clone()
	require.NoError(t, err)
	require.NoError(t, selectHashIfReady(serverTranscript, fixture.serverState.CipherSuite))
	require.NoError(t, AppendOutboundHandshakeFlight(
		serverTranscript,
		false,
		fixture.serverState.CipherSuite,
		fixture.serverFlight4[:5],
	))
	baseKey, err := ServerHandshakeFinishedBaseKey(fixture.serverState)
	require.NoError(t, err)
	finished.VerifyData, err = FinishedVerifyDataFromTranscript(
		fixture.serverState.CipherSuite.HashFunc(),
		baseKey,
		serverTranscript,
	)
	require.NoError(t, err)

	return fixture
}

type noHRRFlight13Fixture struct {
	clientState   *dtlsstate.State13
	serverState   *dtlsstate.State13
	cfg           *dtlsconfig.HandshakeConfig
	clientHello   []*dtlsflight.Outbound
	transcript    *Transcript
	serverFlight4 []*dtlsflight.Outbound
}

func newNoHRRFlight13Fixture(t *testing.T) noHRRFlight13Fixture {
	t.Helper()

	cfg := testHandshakeConfig13(t)
	cfg.InsecureSkipHelloVerify = true

	clientState, clientHello, transcript := newFlight13ClientHelloFixture(t, cfg)
	serverState := newTestState13(t, false)
	serverCache := dtlsflight.NewCache()

	_, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight0, &handshakeContext{
		state: serverState,
		cache: serverCache,
		cfg:   cfg,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	pushFlight13HandshakePacketsToCache(t, serverCache, clientHello, true)

	nextFlight, dtlsAlert, err, ok := dtlsflight13.Parse(
		context.Background(),
		dtlsflight13.Flight0,
		nil,
		dtlsflight13.ParseDependencies{
			State:  serverState,
			Cache:  serverCache,
			Config: cfg,
		},
	)
	require.True(t, ok)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Equal(t, dtlsflight13.Flight4, nextFlight)

	serverTranscript := NewTranscript()
	require.NoError(t, AppendOutboundHandshakeFlight(serverTranscript, true, nil, clientHello))
	serverFSM, err := newFSM13(serverState, serverCache, cfg, dtlsflight13.Flight4, nil, serverTranscript)
	require.NoError(t, err)
	nextState, err := serverFSM.prepare(context.Background(), &flightTestConn{})
	require.NoError(t, err)
	require.Equal(t, StateSending, nextState)
	serverFlight4 := serverFSM.flights
	require.Len(t, serverFlight4, 5)
	for i, pkt := range serverFlight4 {
		setFlight13HandshakeSequence(t, pkt, uint16(i))
	}

	return noHRRFlight13Fixture{
		clientState:   clientState,
		serverState:   serverState,
		cfg:           cfg,
		clientHello:   clientHello,
		transcript:    transcript,
		serverFlight4: serverFlight4,
	}
}

func newFlight13ClientHelloFixture(
	t *testing.T,
	cfg *dtlsconfig.HandshakeConfig,
) (*dtlsstate.State13, []*dtlsflight.Outbound, *Transcript) {
	t.Helper()

	clientState := newTestState13(t, true)
	clientHello, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeContext{
		state: clientState,
		cache: dtlsflight.NewCache(),
		cfg:   cfg,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, clientHello, 1)
	setFlight13HandshakeSequence(t, clientHello[0], 0)
	clientState.HandshakeSendSequence = 1

	transcript := NewTranscript()
	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, nil, clientHello))

	return clientState, clientHello, transcript
}

func pushFlight13HandshakePacketsToCache(
	t *testing.T,
	cache *dtlsflight.Cache,
	pkts []*dtlsflight.Outbound,
	isClient bool,
) {
	t.Helper()

	for _, p := range pkts {
		content, ok := p.Content.(*handshake.Handshake)
		require.True(t, ok)
		raw, err := content.Marshal()
		require.NoError(t, err)
		cache.Push(
			raw,
			p.Epoch,
			content.Header.MessageSequence,
			content.Message.Type(),
			isClient,
		)
	}
}

func setFlight13HandshakeSequence(t *testing.T, p *dtlsflight.Outbound, seq uint16) {
	t.Helper()

	content, ok := p.Content.(*handshake.Handshake)
	require.True(t, ok)
	content.Header.MessageSequence = seq
}

func assertFlight13RecvDoneClosed(t *testing.T, state RecvHandshakeState) {
	t.Helper()

	select {
	case <-state.Done:
	default:
		assert.Fail(t, "state.Done is not closed")
	}
}

func assertFlight13RecvDoneOpen(t *testing.T, state RecvHandshakeState) {
	t.Helper()

	select {
	case <-state.Done:
		assert.Fail(t, "state.Done is closed")
	default:
	}
}

func assertFlight13ClientTranscriptThroughServerFinished(t *testing.T, transcript *Transcript) {
	t.Helper()

	require.Len(t, transcript.order, 6)
	assert.Equal(t, []transcriptMessage{
		{ID: transcriptMessageID{sender: transcriptSenderClient, Seq: 0}, Type: handshake.TypeClientHello},
		{ID: transcriptMessageID{sender: transcriptSenderServer, Seq: 0}, Type: handshake.TypeServerHello},
		{ID: transcriptMessageID{sender: transcriptSenderServer, Seq: 1}, Type: handshake.TypeEncryptedExtensions},
		{ID: transcriptMessageID{sender: transcriptSenderServer, Seq: 2}, Type: handshake.TypeCertificate},
		{ID: transcriptMessageID{sender: transcriptSenderServer, Seq: 3}, Type: handshake.TypeCertificateVerify},
		{ID: transcriptMessageID{sender: transcriptSenderServer, Seq: 4}, Type: handshake.TypeFinished},
	}, transcript.order)
}

func testHandshakeConfig13(t *testing.T) *dtlsconfig.HandshakeConfig {
	t.Helper()

	cipherSuite := ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil)
	require.NotNil(t, cipherSuite)
	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	loggerFactory := logging.NewDefaultLoggerFactory()

	return &dtlsconfig.HandshakeConfig{
		LocalCertificates:           []tls.Certificate{certificate},
		InsecureSkipVerify:          true,
		LocalCipherSuites:           []dtlsconfig.CipherSuite{cipherSuite},
		EllipticCurves:              testCurves13,
		InitialRetransmitInterval:   time.Second,
		ExtendedMasterSecret:        dtlsconfig.RequestExtendedMasterSecret,
		Log:                         loggerFactory.NewLogger("dtls"),
		MinVersion:                  protocol.Version1_3,
		MaxVersion:                  protocol.Version1_3,
		LocalSignatureSchemes:       signaturehash.Algorithms(),
		LocalCertSignatureSchemes:   nil,
		LocalSRTPProtectionProfiles: nil,
	}
}

func TestAppendOutboundHandshakeFlight13ClientHello(t *testing.T) {
	transcript := NewTranscript()
	pkt := transcriptTestClientHelloPacket13([]byte{0x01}, 3)
	expected := canonicalPacketHandshake13(t, pkt)

	err := AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Outbound{pkt})
	require.NoError(t, err)
	require.Len(t, transcript.order, 1)
	require.Len(t, transcript.pending, 1)

	assert.Equal(t, transcriptMessageID{sender: transcriptSenderClient, Seq: 3}, transcript.order[0].ID)
	assert.Equal(t, handshake.TypeClientHello, transcript.order[0].Type)
	assert.Equal(t, expected, transcript.pending[0])
	assert.Equal(t, expected, transcript.Bytes())
}

func TestAppendOutboundHandshakeFlight13DuplicateNoop(t *testing.T) {
	transcript := NewTranscript()
	pkt := transcriptTestClientHelloPacket13([]byte{0x01}, 0)

	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Outbound{pkt}))
	before := append([]byte(nil), transcript.Bytes()...)

	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Outbound{pkt}))
	assert.Equal(t, before, transcript.Bytes())
	assert.Len(t, transcript.order, 1)
}

func TestAppendOutboundHandshakeFlight13ChangedSameSequenceFails(t *testing.T) {
	transcript := NewTranscript()
	pkt := transcriptTestClientHelloPacket13([]byte{0x01}, 0)
	changedPkt := transcriptTestClientHelloPacket13([]byte{0x02}, 0)

	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Outbound{pkt}))
	err := AppendOutboundHandshakeFlight(transcript, true, nil, []*dtlsflight.Outbound{changedPkt})

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

	require.NoError(t, AppendOutboundHandshakeFlight(transcript, true, cipherSuite, []*dtlsflight.Outbound{clientHello}))
	require.NoError(t, AppendOutboundHandshakeFlight(
		transcript, false, cipherSuite, []*dtlsflight.Outbound{helloRetryRequest},
	))

	clientHelloHash := hashTranscript13(clientHelloCanonical)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHelloHash)
	expectedTranscript := append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...)
	assert.Equal(t, expectedTranscript, transcript.Bytes())

	sum, err := transcript.SnapshotHash()
	require.NoError(t, err)
	assert.Equal(t, hashTranscript13(messageHash, helloRetryRequestCanonical), sum)
	require.Len(t, transcript.order, 2)
	assert.Equal(t, handshake.TypeClientHello, transcript.order[0].Type)
	assert.Equal(t, handshake.TypeServerHello, transcript.order[1].Type)

	before := append([]byte(nil), transcript.Bytes()...)
	require.NoError(t, AppendOutboundHandshakeFlight(
		transcript, false, cipherSuite, []*dtlsflight.Outbound{helloRetryRequest},
	))
	assert.Equal(t, before, transcript.Bytes())
	assert.Len(t, transcript.order, 2)
}

func transcriptTestClientHelloPacket13(sessionID []byte, seq uint16) *dtlsflight.Outbound {
	return &dtlsflight.Outbound{
		Content: &handshake.Handshake{
			Header: handshake.Header{MessageSequence: seq},
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				SessionID:          sessionID,
				CipherSuiteIDs:     []uint16{uint16(ciphersuite.TLS_AES_128_GCM_SHA256)},
				CompressionMethods: dtlsflight.DefaultCompressionMethods(),
			},
		},
	}
}

func transcriptTestHelloRetryRequestPacket13(
	tb testing.TB, cipherSuite dtlsconfig.CipherSuite, seq uint16,
) *dtlsflight.Outbound {
	tb.Helper()

	random := handshake.Random{}
	random.UnmarshalFixed([32]byte(handshake.HelloRetryRequestRandom()))
	cipherSuiteID := uint16(cipherSuite.ID())

	return &dtlsflight.Outbound{
		Content: &handshake.Handshake{
			Header: handshake.Header{MessageSequence: seq},
			Message: &handshake.MessageServerHello{
				Version:           protocol.Version1_2,
				Random:            random,
				CipherSuiteID:     &cipherSuiteID,
				CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
				Extensions: []extension.Value{
					&extension13.SelectedVersion{
						Version: protocol.Version1_3,
					},
				},
			},
		},
	}
}
