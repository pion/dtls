// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite/types"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlscrypto "github.com/pion/dtls/v3/internal/handshakecrypto"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// [RFC9147 Section-5.8.1]
//                            +-----------+
//                            | PREPARING |
//               +----------> |           |
//               |            |           |
//               |            +-----------+
//               |                  |
//               |                  | Buffer next flight
//               |                  |
//               |                 \|/
//               |            +-----------+
//               |            |           |
//               |            |  SENDING  |<------------------+
//               |            |           |                   |
//               |            +-----------+                   |
//       Receive |                  |                         |
//          next |                  | Send flight or partial  |
//        flight |                  | flight                  |
//               |                  |                         |
//               |                  | Set retransmit timer    |
//               |                 \|/                        |
//               |            +-----------+                   |
//               |            |           |                   |
//               +------------|  WAITING  |-------------------+
//               |     +----->|           |   Timer expires   |
//               |     |      +-----------+                   |
//               |     |          |  |   |                    |
//               |     |          |  |   |                    |
//               |     +----------+  |   +--------------------+
//               |    Receive record |   Read retransmit or ACK
//       Receive |  (Maybe Send ACK) |
//          last |                   |
//        flight |                   | Receive ACK
//               |                   | for last flight
//              \|/                  |
//                                   |
//           +-----------+           |
//           |           | <---------+
//           | FINISHED  |
//           |           |
//           +-----------+
//               |  /|\
//               |   |
//               |   |
//               +---+
//
//         Server read retransmit
//             Retransmit ACK

type fsm13 struct {
	currentFlight      dtlsflight13.Flight
	flights            []*dtlsflight.Packet
	retransmit         bool
	retransmitInterval time.Duration
	state              *dtlsstate.State13
	cache              *dtlsflight.Cache
	cfg                *dtlsconfig.HandshakeConfig
	transcript         *Transcript
	closed             chan struct{}
	establishment      *Establishment
	pendingRecvDone    chan struct{} // keeps the reader paused across a prepare/send transition
}

type receivedFlightTransition struct {
	state             State
	retainPendingRecv bool
}

func NewFSM13(
	state *dtlsstate.State13,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	initialFlight dtlsflight13.Flight,
	initialFlights []*dtlsflight.Packet,
	establishment *Establishment,
) (FSM, error) {
	return newFSM13WithEstablishment(state, cache, cfg, initialFlight, initialFlights, nil, establishment)
}

func newFSM13(
	state *dtlsstate.State13,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	initialFlight dtlsflight13.Flight,
	initialFlights []*dtlsflight.Packet,
	initialTranscript *Transcript,
) (*fsm13, error) {
	return newFSM13WithEstablishment(
		state, cache, cfg, initialFlight, initialFlights, initialTranscript, NewEstablishment(),
	)
}

func newFSM13WithEstablishment(
	state *dtlsstate.State13,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	initialFlight dtlsflight13.Flight,
	initialFlights []*dtlsflight.Packet,
	initialTranscript *Transcript,
	establishment *Establishment,
) (*fsm13, error) {
	if initialTranscript == nil {
		initialTranscript = NewTranscript()
	}

	fsm := &fsm13{
		currentFlight:      initialFlight,
		flights:            initialFlights,
		retransmit:         initialFlights != nil,
		state:              state,
		cache:              cache,
		cfg:                cfg,
		transcript:         initialTranscript,
		retransmitInterval: cfg.InitialRetransmitInterval,
		closed:             make(chan struct{}),
		establishment:      establishment,
	}
	if err := fsm.seedTranscriptFromInitialFlights(); err != nil {
		return nil, err
	}

	return fsm, nil
}

// seedTranscriptFromInitialFlights imports the dual-stack ClientHello generated
// before the DTLS 1.3 FSM exists.
func (s *fsm13) seedTranscriptFromInitialFlights() error {
	if !s.state.IsClient {
		return nil
	}

	appended, err := AppendClientHelloInitialFlights(s.transcript, s.flights)
	if err != nil {
		return err
	}
	if s.retransmit && !appended {
		return dtlserrors.ErrHandshakeTranscriptMissingClientHello
	}

	return nil
}

func AppendClientHelloInitialFlights(transcript *Transcript, flights []*dtlsflight.Packet) (bool, error) {
	if transcript == nil {
		return false, dtlserrors.ErrHandshakeTranscriptMissingClientHello
	}

	appended := false
	for _, p := range flights {
		seq, canonical, ok, err := canonicalClientHelloInitialFlight13(p)
		if err != nil {
			return false, err
		}
		if !ok {
			continue
		}
		if err := transcript.appendCanonical(transcriptMessageID{
			sender: transcriptSenderClient,
			Seq:    seq,
		}, canonical); err != nil {
			return false, err
		}
		appended = true
	}

	return appended, nil
}

// ValidateClientHelloInitialFlights verifies that the dual-stack initial flight
// contains a canonical ClientHello before it is written.
func ValidateClientHelloInitialFlights(flights []*dtlsflight.Packet) error {
	appended, err := AppendClientHelloInitialFlights(NewTranscript(), flights)
	if err != nil {
		return err
	}
	if !appended {
		return dtlserrors.ErrHandshakeTranscriptMissingClientHello
	}

	return nil
}

func canonicalClientHelloInitialFlight13(p *dtlsflight.Packet) (uint16, []byte, bool, error) {
	if p == nil || p.Record == nil {
		return 0, nil, false, nil
	}
	hand, ok := p.Record.Content.(*handshake.Handshake)
	if !ok {
		return 0, nil, false, nil
	}
	if hand.Message == nil || hand.Message.Type() != handshake.TypeClientHello {
		return 0, nil, false, nil
	}

	raw, err := hand.Marshal()
	if err != nil {
		return 0, nil, false, err
	}
	canonical, err := canonicalHandshake(raw)
	if err != nil {
		return 0, nil, false, err
	}

	return hand.Header.MessageSequence, canonical, true, nil
}

func (s *fsm13) Run(ctx context.Context, conn Conn, initialState State) error {
	defer s.releasePendingRecv()

	return runHandshakeFSM(
		ctx,
		conn,
		initialState,
		s.closed,
		s.establishment,
		func(state State) {
			s.cfg.Log.Tracef(
				"[handshake13:%s] %s: %s",
				sideString(s.state.IsClient),
				s.currentFlight.String(),
				state.String(),
			)
		},
		s.prepare,
		s.send,
		s.wait,
		s.finish,
	)
}

func (s *fsm13) Done() <-chan struct{} {
	return s.closed
}

func (s *fsm13) prepare(ctx context.Context, conn Conn) (nextState State, err error) {
	defer func() {
		if err != nil {
			s.releasePendingRecv()
		}
	}()

	s.flights = nil
	// Prepare flights
	var (
		dtlsAlert *alert.Alert
		pkts      []*dtlsflight.Packet
	)
	gen, retransmit, ok := dtlsflight13.GetGenerator(s.currentFlight)
	if !ok {
		err = dtlserrors.ErrFlightUnimplemented13
		dtlsAlert = &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}
	} else {
		pkts, dtlsAlert, err = gen(conn, s.state, s.cache, s.cfg)
		s.retransmit = retransmit
	}
	if err = notifyAlert(ctx, conn, dtlsAlert, err); err != nil {
		return StateErrored, err
	}

	s.flights = pkts
	if err := s.commitPreparedFlights(conn); err != nil {
		return StateErrored, err
	}
	if !s.state.IsClient && s.currentFlight == dtlsflight13.Flight4 {
		if err := DeriveAndStoreApplicationTrafficSecrets(s.state, s.transcript); err != nil {
			return StateErrored, err
		}
	}

	return StateSending, nil
}

func (s *fsm13) commitPreparedFlights(conn Conn) error { //nolint:cyclop,nestif
	epoch := s.cfg.InitialEpoch
	nextEpoch := epoch
	protectedFlightStart := len(s.flights)
	for i, p := range s.flights {
		p.Record.Header.Epoch += epoch
		if p.Record.Header.Epoch > nextEpoch {
			nextEpoch = p.Record.Header.Epoch
		}
		if p.ShouldEncrypt && protectedFlightStart == len(s.flights) {
			protectedFlightStart = i
		}
		if h, ok := p.Record.Content.(*handshake.Handshake); ok {
			h.Header.MessageSequence = uint16(s.state.HandshakeSendSequence) //nolint:gosec // G115
			s.state.HandshakeSendSequence++
		}
	}

	if protectedFlightStart == len(s.flights) { //nolint:nestif
		if err := s.appendCommittedOutboundHandshakeFlight(s.flights); err != nil {
			return err
		}
	} else {
		if err := s.appendCommittedOutboundHandshakeFlight(s.flights[:protectedFlightStart]); err != nil {
			return err
		}
		if err := s.ensureHandshakeTrafficSecrets(); err != nil {
			return err
		}
		if err := InitHandshakeRecordProtection(s.state); err != nil {
			return err
		}
		if err := s.appendCommittedOutboundHandshakeFlight(s.flights[protectedFlightStart:]); err != nil {
			return err
		}
	}

	if epoch != nextEpoch {
		s.cfg.Log.Tracef("[handshake13:%s] -> changeCipherSpec (epoch: %d)", sideString(s.state.IsClient), nextEpoch)
		conn.SetLocalEpoch(nextEpoch)
	}

	return nil
}

func (s *fsm13) ensureHandshakeTrafficSecrets() error {
	secrets := s.state.KeySchedule.HandshakeTraffic
	if len(secrets.Client) == 0 && len(secrets.Server) == 0 {
		return DeriveAndStoreHandshakeTrafficSecrets(s.state, s.transcript)
	}

	return selectHashIfReady(s.transcript, s.state.CipherSuite)
}

func (s *fsm13) appendCommittedOutboundHandshakeFlight(pkts []*dtlsflight.Packet) error {
	for _, p := range pkts {
		if err := s.populateOutboundCertificateVerify(p); err != nil {
			return err
		}
		if err := s.populateOutboundFinished(p); err != nil {
			return err
		}
		if err := AppendOutboundHandshakeFlight(
			s.transcript,
			s.state.IsClient,
			s.state.CipherSuite,
			[]*dtlsflight.Packet{p},
		); err != nil {
			return err
		}
	}

	return nil
}

func (s *fsm13) populateOutboundCertificateVerify(pkt *dtlsflight.Packet) error {
	if pkt == nil || pkt.Record == nil {
		return nil
	}
	h, ok := pkt.Record.Content.(*handshake.Handshake)
	if !ok {
		return nil
	}
	certificateVerify, ok := h.Message.(*handshake.MessageCertificateVerify)
	if !ok || len(certificateVerify.Signature) != 0 {
		return nil
	}
	if pkt.CertificateVerifySigner == nil {
		return dtlserrors.ErrInvalidPrivateKey
	}

	input, err := CertificateVerifyInputFromTranscript(s.state.IsClient, s.transcript)
	if err != nil {
		return err
	}
	certificateVerify.Signature, err = dtlscrypto.GenerateCertificateVerify(
		input,
		pkt.CertificateVerifySigner,
		certificateVerify.HashAlgorithm,
		certificateVerify.SignatureAlgorithm,
	)

	return err
}

func (s *fsm13) populateOutboundFinished(p *dtlsflight.Packet) error {
	if p == nil || p.Record == nil {
		return nil
	}
	h, ok := p.Record.Content.(*handshake.Handshake)
	if !ok {
		return nil
	}
	finished, ok := h.Message.(*handshake.MessageFinished)
	if !ok || len(finished.VerifyData) != 0 {
		return nil
	}
	if s.state.CipherSuite == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}

	baseKey, err := ServerHandshakeFinishedBaseKey(s.state)
	if s.state.IsClient {
		baseKey, err = ClientHandshakeFinishedBaseKey(s.state)
	}
	if err != nil {
		return err
	}

	verifyData, err := FinishedVerifyDataFromTranscript(s.state.CipherSuite.HashFunc(), baseKey, s.transcript)
	if err != nil {
		return err
	}
	finished.VerifyData = verifyData

	return nil
}

func (s *fsm13) send(ctx context.Context, conn Conn) (State, error) {
	defer s.releasePendingRecv()

	if err := conn.WritePackets(ctx, s.flights); err != nil {
		return StateErrored, err
	}
	if !s.state.IsClient &&
		s.currentFlight == dtlsflight13.Flight4 &&
		s.state.GetRemoteEpoch() < dtlsflight13.EpochHandshake {
		// Only the first send advances the epoch and drains packets. A timer
		// retransmission has no receive-side rendezvous and the reader is active.
		s.state.RemoteEpoch.Store(dtlsflight13.EpochHandshake)
		if err := conn.HandleQueuedPackets(ctx); err != nil {
			return StateErrored, err
		}
	}
	if s.state.IsClient && s.currentFlight == dtlsflight13.Flight5 {
		if err := s.activateApplicationRecordProtection(ctx, conn); err != nil {
			return StateErrored, err
		}

		return StateFinished, nil
	}

	return StateWaiting, nil
}

func (s *fsm13) transitionRequiresReaderPause(nextFlight dtlsflight13.Flight) bool {
	if s.state.IsClient {
		return nextFlight == dtlsflight13.Flight5
	}

	return nextFlight == dtlsflight13.Flight4 &&
		s.state.GetRemoteEpoch() < dtlsflight13.EpochHandshake
}

func (s *fsm13) wait(ctx context.Context, conn Conn) (State, error) {
	retainPendingRecv := false
	defer func() {
		if !retainPendingRecv {
			s.releasePendingRecv()
		}
	}()

	retransmitTimer := time.NewTimer(s.retransmitInterval)
	defer retransmitTimer.Stop()
	for {
		select {
		case received := <-conn.RecvHandshake():
			nextFlight, err := s.parseReceivedFlight(ctx, conn, received)
			if err != nil {
				return StateErrored, err
			}
			if nextFlight == 0 {
				s.releasePendingRecv()

				continue
			}

			transition, err := s.advanceAfterReceivedFlight(ctx, conn, nextFlight, received.Records)
			if err != nil {
				return StateErrored, err
			}
			retainPendingRecv = transition.retainPendingRecv

			return transition.state, nil

		case <-retransmitTimer.C:
			return s.handleRetransmitTimeout(), nil
		case <-ctx.Done():
			return s.handleWaitCancellation(ctx.Err())
		}
	}
}

func (s *fsm13) parseReceivedFlight(
	ctx context.Context,
	conn Conn,
	received RecvHandshakeState,
) (dtlsflight13.Flight, error) {
	// Keep the reader paused while this receive state is parsed.
	s.pendingRecvDone = received.Done
	if !received.IsRetransmit {
		s.retransmitInterval = s.cfg.InitialRetransmitInterval
	}

	nextFlight, dtlsAlert, err, ok := dtlsflight13.Parse(
		ctx,
		s.currentFlight,
		conn,
		s.parseDependencies(),
	)
	if !ok {
		if alertErr := conn.Notify(ctx, alert.Fatal, alert.InternalError); alertErr != nil {
			return 0, alertErr
		}

		return 0, dtlserrors.ErrFlightUnimplemented13
	}
	if err = notifyAlert(ctx, conn, dtlsAlert, err); err != nil {
		return 0, err
	}

	return nextFlight, nil
}

func (s *fsm13) advanceAfterReceivedFlight(
	ctx context.Context,
	conn Conn,
	nextFlight dtlsflight13.Flight,
	receivedRecords []protocol.RecordNumber,
) (receivedFlightTransition, error) {
	if s.state.IsClient && nextFlight == dtlsflight13.Flight5 {
		if err := DeriveAndStoreApplicationTrafficSecrets(s.state, s.transcript); err != nil {
			return receivedFlightTransition{}, err
		}
	}
	if !s.state.IsClient &&
		s.currentFlight == dtlsflight13.Flight4 &&
		nextFlight == dtlsflight13.Flight4 {
		if err := s.activateApplicationRecordProtection(ctx, conn); err != nil {
			return receivedFlightTransition{}, err
		}
		if err := s.sendACK(ctx, conn, receivedRecords); err != nil {
			return receivedFlightTransition{}, err
		}

		return receivedFlightTransition{state: StateFinished}, nil
	}

	s.cfg.Log.Tracef(
		"[handshake13:%s] %s -> %s",
		sideString(s.state.IsClient),
		s.currentFlight.String(),
		nextFlight.String(),
	)
	transition := receivedFlightTransition{
		state:             StatePreparing,
		retainPendingRecv: s.transitionRequiresReaderPause(nextFlight),
	}
	s.currentFlight = nextFlight

	return transition, nil
}

func (s *fsm13) handleRetransmitTimeout() State {
	if !s.retransmit {
		return StateWaiting
	}

	if !s.cfg.DisableRetransmitBackoff {
		s.retransmitInterval *= 2
	}
	if s.retransmitInterval > time.Second*60 {
		s.retransmitInterval = time.Second * 60
	}

	return StateSending
}

func (s *fsm13) handleWaitCancellation(err error) (State, error) {
	s.retransmitInterval = s.cfg.InitialRetransmitInterval

	return StateErrored, err
}

func (s *fsm13) parseDependencies() dtlsflight13.ParseDependencies {
	return dtlsflight13.ParseDependencies{
		State:  s.state,
		Cache:  s.cache,
		Config: s.cfg,
		Hooks: dtlsflight13.ParseHooks{
			InboundHandshake: func(cipherSuite dtlsconfig.CipherSuite, items []*dtlsflight.HandshakeCacheItem) error {
				return AppendVerifiedInboundHandshakeCacheItems(s.transcript, cipherSuite, items)
			},
			ProtectedHandshake: func(cipherSuite dtlsconfig.CipherSuite, items []*dtlsflight.HandshakeCacheItem) error {
				return VerifyAndAppendProtectedHandshakeCacheItems13(
					s.transcript,
					s.state,
					s.cfg,
					cipherSuite,
					items,
				)
			},
			HandshakeTrafficSecretDeriver: func(state *dtlsstate.State13) error {
				return DeriveAndStoreHandshakeTrafficSecrets(state, s.transcript)
			},
			HandshakeRecordProtectionInitializer: InitHandshakeRecordProtection,
		},
	}
}

func (s *fsm13) releasePendingRecv() {
	if s.pendingRecvDone == nil {
		return
	}

	close(s.pendingRecvDone)
	s.pendingRecvDone = nil
}

func (s *fsm13) finish(ctx context.Context, c Conn) (State, error) {
	select {
	case state := <-c.RecvHandshake():
		close(state.Done)

		// avoid committing a second time.
		return StateFinished, nil
	case <-ctx.Done():
		return StateErrored, ctx.Err()
	}
}

func (s *fsm13) activateApplicationRecordProtection(ctx context.Context, c Conn) error {
	if err := InitApplicationRecordProtection(s.state); err != nil {
		return err
	}
	c.SetLocalEpoch(dtlsflight13.EpochApplication)
	s.state.RemoteEpoch.Store(dtlsflight13.EpochApplication)

	return c.HandleQueuedPackets(ctx)
}

func (s *fsm13) sendACK(ctx context.Context, c Conn, records []protocol.RecordNumber) error {
	if len(records) == 0 {
		return nil
	}

	epoch := s.state.GetLocalEpoch()

	return c.WritePackets(ctx, []*dtlsflight.Packet{{
		Record: &recordlayer.RecordLayer{
			Header:  recordlayer.Header{Version: protocol.Version1_2, Epoch: epoch},
			Content: &protocol.ACK{Records: records},
		},
		ShouldEncrypt: true,
	}})
}

func transcriptSenderForSide13(isClient bool) transcriptSender {
	if isClient {
		return transcriptSenderClient
	}

	return transcriptSenderServer
}

func AppendOutboundHandshakeFlight(
	transcript *Transcript,
	isClient bool,
	cipherSuite dtlsconfig.CipherSuite,
	pkts []*dtlsflight.Packet,
) error {
	if transcript == nil {
		return nil
	}

	sender := transcriptSenderForSide13(isClient)
	for _, p := range pkts {
		h, canonical, ok, err := canonicalOutboundHandshake13(p)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}

		if err := appendOutboundHandshake13(transcript, sender, cipherSuite, h, canonical); err != nil {
			return err
		}
	}

	return nil
}

func canonicalOutboundHandshake13(p *dtlsflight.Packet) (*handshake.Handshake, []byte, bool, error) {
	if p == nil || p.Record == nil {
		return nil, nil, false, nil
	}

	hs, ok := p.Record.Content.(*handshake.Handshake)
	if !ok || hs.Message == nil {
		return nil, nil, false, nil
	}

	raw, err := hs.Marshal()
	if err != nil {
		return nil, nil, false, err
	}
	canonical, err := canonicalHandshake(raw)
	if err != nil {
		return nil, nil, false, err
	}

	return hs, canonical, true, nil
}

func appendOutboundHandshake13(
	transcript *Transcript,
	sender transcriptSender,
	cipherSuite dtlsconfig.CipherSuite,
	h *handshake.Handshake,
	canonical []byte,
) error {
	return appendHandshake13(transcript, sender, cipherSuite, h.Header.MessageSequence, h.Message, canonical)
}

// AppendVerifiedInbound appends an inbound handshake message to the transcript
// after the caller has validated and accepted it. For CertificateVerify and
// Finished, callers must authenticate the message against SnapshotHash before
// calling this method.
func (t *Transcript) AppendVerifiedInbound(
	isClient bool,
	cipherSuite dtlsconfig.CipherSuite,
	raw []byte,
) error {
	if t == nil {
		return nil
	}

	canonical, err := canonicalHandshake(raw)
	if err != nil {
		return err
	}

	var keyExchangeAlgorithm types.KeyExchangeAlgorithm
	if cipherSuite != nil {
		keyExchangeAlgorithm = cipherSuite.KeyExchangeAlgorithm()
	}

	h := &handshake.Handshake{
		KeyExchangeAlgorithm: keyExchangeAlgorithm,
	}
	if err := h.Unmarshal(raw); err != nil {
		return err
	}

	return appendHandshake13(
		t,
		transcriptSenderForSide13(isClient),
		cipherSuite,
		h.Header.MessageSequence,
		h.Message,
		canonical,
	)
}

// AppendVerifiedInboundHandshakeCacheItems appends inbound cache items to the
// transcript after the caller has validated and accepted each item.
//
// Messages that require explicit authentication, such as CertificateVerify and
// Finished, must be verified first and then appended with AppendVerifiedInbound.
func AppendVerifiedInboundHandshakeCacheItems(
	transcript *Transcript,
	cipherSuite dtlsconfig.CipherSuite,
	items []*dtlsflight.HandshakeCacheItem,
) error {
	if transcript == nil {
		return nil
	}

	for _, item := range items {
		if requiresExplicitAuthenticationBeforeTranscriptCommit(item.Typ) {
			return dtlserrors.ErrHandshakeTranscriptExplicitAuthenticationRequired
		}
		if err := transcript.AppendVerifiedInbound(item.IsClient, cipherSuite, item.Data); err != nil {
			return err
		}
	}

	return nil
}

func requiresExplicitAuthenticationBeforeTranscriptCommit(typ handshake.Type) bool {
	return typ == handshake.TypeCertificateVerify || typ == handshake.TypeFinished
}

func appendHandshake13(
	transcript *Transcript,
	sender transcriptSender,
	cipherSuite dtlsconfig.CipherSuite,
	seq uint16,
	message handshake.Message,
	canonical []byte,
) error {
	id := transcriptMessageID{
		sender: sender,
		Seq:    seq,
	}
	if sh, ok := message.(*handshake.MessageServerHello); ok && dtlsflight13.IsHelloRetryRequest(sh) {
		duplicate, err := transcript.hasCanonical(id, canonical)
		if err != nil || duplicate {
			return err
		}

		if err := selectHashIfReady(transcript, cipherSuite); err != nil {
			return err
		}
		if err := transcript.applyHelloRetryRequest(); err != nil {
			return err
		}
	}

	return transcript.appendCanonical(id, canonical)
}
