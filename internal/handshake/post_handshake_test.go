// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type postHandshakeAlert struct {
	level       alert.Level
	description alert.Description
}

type postHandshakeAlertConn struct {
	flightTestConn

	notifications []postHandshakeAlert
	notifyErr     error
}

func (c *postHandshakeAlertConn) Notify(
	_ context.Context,
	level alert.Level,
	description alert.Description,
) error {
	c.notifications = append(c.notifications, postHandshakeAlert{
		level:       level,
		description: description,
	})

	return c.notifyErr
}

type postHandshakeWriteConn struct {
	flightTestConn
	result *WriteResult
}

type postHandshakeKeyUpdateConn struct {
	flightTestConn
	state     *dtlsstate.State13
	result    *WriteResult
	committed *dtlsstate.TrafficGeneration
}

func (c *postHandshakeKeyUpdateConn) WritePackets(
	_ context.Context,
	pkts []*dtlsflight.Outbound,
) (*WriteResult, error) {
	c.writtenPackets = append(c.writtenPackets, pkts...)
	if c.result == nil {
		return &WriteResult{}, nil
	}

	return c.result, nil
}

func (c *postHandshakeKeyUpdateConn) CommitLocalKeyUpdate(generation *dtlsstate.TrafficGeneration) error {
	c.committed = generation
	c.state.TrafficKeys.Install(generation, nil)
	c.state.SetLocalEpoch(generation.Epoch)

	return nil
}

func newPostHandshakeKeyUpdateTestState(t *testing.T, isClient bool) *dtlsstate.State13 {
	t.Helper()

	state := dtlsstate.NewState13(isClient)
	suite := ciphersuite.NewTLSAes128GcmSha256()
	state.CipherSuite = suite
	state.SetLocalEpoch(dtlsflight13.EpochApplication)
	state.SetRemoteEpoch(dtlsflight13.EpochApplication)
	writeSecret := bytes.Repeat([]byte{0x11}, suite.HashFunc()().Size())
	readSecret := bytes.Repeat([]byte{0x22}, suite.HashFunc()().Size())
	writeProtection, err := suite.NewRecordProtection(writeSecret)
	require.NoError(t, err)
	readProtection, err := suite.NewRecordProtection(readSecret)
	require.NoError(t, err)
	state.TrafficKeys.Install(
		&dtlsstate.TrafficGeneration{
			Epoch:      dtlsflight13.EpochApplication,
			Secret:     writeSecret,
			Protection: writeProtection,
		},
		&dtlsstate.TrafficGeneration{
			Epoch:      dtlsflight13.EpochApplication,
			Secret:     readSecret,
			Protection: readProtection,
		},
	)

	return &state
}

func (c *postHandshakeWriteConn) WritePackets(
	_ context.Context,
	pkts []*dtlsflight.Outbound,
) (*WriteResult, error) {
	c.writtenPackets = append(c.writtenPackets, pkts...)

	return c.result, nil
}

func TestMakeReliableNewSessionTicket(t *testing.T) {
	state := dtlsstate.NewState13(false)
	state.SetLocalEpoch(7)
	state.HandshakeSendSequence = 12
	post := newPostHandshake(handshakeContext{
		state: &state,
		cfg:   &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second},
	})
	message := &handshake.MessageNewSessionTicket{
		TicketLifetime: newSessionTicketLifetime,
		TicketAgeAdd:   42,
		TicketNonce:    []byte{1},
		Ticket:         []byte{2},
	}

	flight, err := post.makeReliableNewSessionTicket(message)
	require.NoError(t, err)
	require.Len(t, flight.Packets, 1)
	packet := flight.Packets[0]
	assert.True(t, packet.Protection == dtlsflight.ProtectionCiphertext)
	assert.True(t, packet.TrackACK)
	assert.Equal(t, uint16(7), packet.Epoch)
	assert.Equal(t, uint16(12), flight.ID.MessageSequence)
	assert.Equal(t, 13, state.HandshakeSendSequence)

	wireHandshake, ok := packet.Content.(*handshake.Handshake)
	require.True(t, ok)
	assert.Equal(t, uint16(12), wireHandshake.Header.MessageSequence)
	assert.Same(t, message, wireHandshake.Message)
}

func TestPostHandshakeACKCompletesReliableFlight(t *testing.T) {
	state := dtlsstate.NewState13(false)
	post := newPostHandshake(handshakeContext{
		state: &state,
		cfg:   &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second},
	})
	id := postHandshakeFlightID{Category: postHandshakeNewSessionTicket, MessageSequence: 4}
	flight := &reliablePostHandshakeFlight{
		ID:               id,
		PendingFragments: make(map[postHandshakeFragment]struct{}),
		SentRecords:      make(map[protocol.RecordNumber]struct{}),
	}
	post.flights[id] = flight
	firstRecord := protocol.RecordNumber{Epoch: 3, SequenceNumber: 10}
	retransmitRecord := protocol.RecordNumber{Epoch: 3, SequenceNumber: 11}
	fragment := SentHandshakeFragment{MessageSequence: 4, Offset: 0, Length: 20}
	post.registerTransmission(flight, []SentHandshakeRecord{{
		Number: firstRecord, Fragments: []SentHandshakeFragment{fragment},
	}}, true)
	post.registerTransmission(flight, []SentHandshakeRecord{{
		Number: retransmitRecord, Fragments: []SentHandshakeFragment{fragment},
	}}, false)

	completed := post.applyACK(protocol.ACK{Records: []protocol.RecordNumber{retransmitRecord}})
	assert.Equal(t, []postHandshakeFlightID{id}, completed)
	assert.Empty(t, flight.PendingFragments)
	_, firstStillIndexed := post.recordIndex[firstRecord]
	assert.True(t, firstStillIndexed)
}

func TestPostHandshakeSkipsCanceledCommand(t *testing.T) {
	state := dtlsstate.NewState13(false)
	post := newPostHandshake(handshakeContext{
		state: &state,
		cfg:   &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	completion, completionCtx := newPostHandshakeCompletion()
	post.queue = append(post.queue, postHandshakeCommand{
		Kind:       commandSendNewSessionTicket,
		Canceled:   ctx.Done(),
		Completion: completion,
	})
	conn := &postHandshakeWriteConn{result: &WriteResult{}}

	require.NoError(t, post.startQueuedPostHandshake(context.Background(), conn))
	<-completionCtx.Done()
	assert.ErrorIs(t, completion.result(), context.Canceled)
	assert.Empty(t, conn.writtenPackets)
	assert.Empty(t, post.queue)
	assert.Empty(t, post.flights)
}

func TestPostHandshakeCompletionKeepsFirstOutcome(t *testing.T) {
	completion, completionCtx := newPostHandshakeCompletion()
	completion.complete(nil)
	completion.complete(assert.AnError)

	<-completionCtx.Done()
	assert.NoError(t, completion.result())
}

func TestWaitPostHandshakeCompletionKeepsCallerCancellationSeparate(t *testing.T) {
	completion, completionCtx := newPostHandshakeCompletion()
	callerCtx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.ErrorIs(t, (&fsm13{}).waitPostHandshakeCompletion(
		callerCtx,
		completionCtx,
		completion,
	), context.Canceled)
	assert.NoError(t, completionCtx.Err())

	completion.complete(nil)
	<-completionCtx.Done()
	assert.NoError(t, completion.result())
}

func TestPostHandshakeACKReliability(t *testing.T) {
	state := dtlsstate.NewState13(false)
	post := newPostHandshake(handshakeContext{
		state: &state,
		cfg:   &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second},
	})
	flight, err := post.makeReliableNewSessionTicket(&handshake.MessageNewSessionTicket{
		TicketLifetime: newSessionTicketLifetime,
		Ticket:         []byte{1},
	})
	require.NoError(t, err)

	messageSequence := flight.ID.MessageSequence
	firstFragment := SentHandshakeFragment{MessageSequence: messageSequence, Length: 10}
	secondFragment := SentHandshakeFragment{MessageSequence: messageSequence, Offset: 10, Length: 10}
	firstRecord := protocol.RecordNumber{Epoch: 3, SequenceNumber: 1}
	secondRecord := protocol.RecordNumber{Epoch: 3, SequenceNumber: 2}
	post.flights[flight.ID] = flight
	post.registerTransmission(flight, []SentHandshakeRecord{
		{Number: firstRecord, Fragments: []SentHandshakeFragment{firstFragment}},
		{Number: secondRecord, Fragments: []SentHandshakeFragment{secondFragment}},
	}, true)

	// A partial ACK retires the first fragment. Receiving it again makes no
	// further progress.
	assert.Empty(t, post.applyACK(protocol.ACK{Records: []protocol.RecordNumber{firstRecord}}))
	assert.Empty(t, post.applyACK(protocol.ACK{Records: []protocol.RecordNumber{firstRecord}}))

	// If the second fragment's ACK is lost, retransmit only that fragment.
	retransmitRecord := protocol.RecordNumber{Epoch: 3, SequenceNumber: 3}
	conn := &postHandshakeWriteConn{result: &WriteResult{TrackedRecords: []SentHandshakeRecord{{
		Number:    retransmitRecord,
		Fragments: []SentHandshakeFragment{secondFragment},
	}}}}
	now := time.Now()
	require.NoError(t, post.retransmitPostHandshakeFlight(context.Background(), conn, flight, now, true))
	require.Len(t, conn.writtenPackets, 1)
	assert.Equal(t, map[uint32]uint32{10: 10}, conn.writtenPackets[0].HandshakeFragmentOffsets)
	assert.Equal(t, now.Add(time.Second), flight.NextRetransmit)

	// The original ACK can arrive after the retransmission and still complete
	// the flight.
	completed := post.applyACK(protocol.ACK{
		Records: []protocol.RecordNumber{secondRecord},
	})
	assert.Equal(t, []postHandshakeFlightID{flight.ID}, completed)
	assert.Empty(t, flight.PendingFragments)
	for _, id := range completed {
		require.NoError(t, post.completePostHandshakeFlight(conn, id))
	}

	// An ACK for a retransmission may arrive after an earlier transmission
	// already completed the flight.
	assert.Empty(t, post.applyACK(protocol.ACK{Records: []protocol.RecordNumber{retransmitRecord}}))
}

func TestPostHandshakeReceiveNewSessionTicket(t *testing.T) {
	const (
		epoch              = uint16(3)
		ticketRecvSequence = uint16(8)
	)
	record := protocol.RecordNumber{Epoch: uint64(epoch), SequenceNumber: 9}

	state := dtlsstate.NewState13(true)
	state.SetLocalEpoch(epoch)
	state.HandshakeRecvSequence = int(ticketRecvSequence)

	cache := dtlsflight.NewCache()
	ticketWire, err := (&handshake.Handshake{
		Header: handshake.Header{
			Type:            handshake.TypeNewSessionTicket,
			MessageSequence: ticketRecvSequence,
		},
		Message: &handshake.MessageNewSessionTicket{
			TicketLifetime: newSessionTicketLifetime,
			TicketNonce:    []byte{1},
			Ticket:         []byte{2},
		},
	}).Marshal()
	require.NoError(t, err)
	cache.Push(ticketWire, epoch, ticketRecvSequence, handshake.TypeNewSessionTicket, false)

	post := newPostHandshake(handshakeContext{
		state: &state,
		cache: cache,
		cfg:   &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second},
	})
	conn := &flightTestConn{}
	receive := func() error {
		return post.handlePostHandshakeReceive(context.Background(), conn, RecvHandshakeState{
			HasHandshake: true,
			RecordsToACK: []protocol.RecordNumber{record},
		})
	}

	require.NoError(t, receive())
	assert.Equal(t, int(ticketRecvSequence)+1, state.HandshakeRecvSequence)
	require.Len(t, conn.writtenPackets, 1)
	firstACK, ok := conn.writtenPackets[0].Content.(*protocol.ACK)
	require.True(t, ok)
	assert.Equal(t, []protocol.RecordNumber{record}, firstACK.Records)

	require.NoError(t, receive())
	assert.Equal(t, int(ticketRecvSequence)+1, state.HandshakeRecvSequence)
	require.Len(t, conn.writtenPackets, 2)
	retransmitACK, ok := conn.writtenPackets[1].Content.(*protocol.ACK)
	require.True(t, ok)
	assert.Equal(t, []protocol.RecordNumber{record}, retransmitACK.Records)
}

func TestProcessPostHandshakeMessagesDecodeAlert(t *testing.T) {
	tests := []struct {
		name        string
		notifyErr   error
		expectedErr error
	}{
		{
			name:        "returns decode failure",
			expectedErr: dtlserrors.ErrBufferTooSmall,
		},
		{
			name:        "notification failure takes precedence",
			notifyErr:   assert.AnError,
			expectedErr: assert.AnError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := dtlsstate.NewState13(true)
			cache := dtlsflight.NewCache()
			cache.Push(
				[]byte{byte(handshake.TypeNewSessionTicket)},
				3,
				0,
				handshake.TypeNewSessionTicket,
				false,
			)
			post := newPostHandshake(handshakeContext{
				state: &state,
				cache: cache,
				cfg:   &dtlsconfig.HandshakeConfig{},
			})
			conn := &postHandshakeAlertConn{notifyErr: test.notifyErr}

			err := post.processPostHandshakeMessages(context.Background(), conn)
			require.ErrorIs(t, err, test.expectedErr)
			assert.Equal(t, []postHandshakeAlert{{
				level:       alert.Fatal,
				description: alert.DecodeError,
			}}, conn.notifications)
			assert.Zero(t, state.HandshakeRecvSequence)
		})
	}
}

func TestProcessPostHandshakeMessagesPreservesExtensionAlert(t *testing.T) {
	wire, err := (&handshake.Handshake{
		Message: &handshake.MessageNewSessionTicket{
			Ticket: []byte{0x01},
			CachedExtensions: extension.CachedList{
				Values: []extension.Value{
					&extension13.MaxEarlyData{Size: 1},
					&extension13.MaxEarlyData{Size: 2},
				},
			},
		},
	}).Marshal()
	require.NoError(t, err)

	state := dtlsstate.NewState13(true)
	cache := dtlsflight.NewCache()
	cache.Push(wire, dtlsflight13.EpochApplication, 0, handshake.TypeNewSessionTicket, false)
	post := newPostHandshake(handshakeContext{
		state: &state,
		cache: cache,
		cfg:   &dtlsconfig.HandshakeConfig{},
	})
	conn := &postHandshakeAlertConn{}

	err = post.processPostHandshakeMessages(context.Background(), conn)
	require.ErrorIs(t, err, dtlserrors.ErrDuplicateExtension)
	assert.Equal(t, []postHandshakeAlert{{
		level:       alert.Fatal,
		description: alert.IllegalParameter,
	}}, conn.notifications)
	assert.Zero(t, state.HandshakeRecvSequence)
}

func TestHandleUnexpectedPostHandshakeMessageAlert(t *testing.T) {
	state := dtlsstate.NewState13(true)
	post := newPostHandshake(handshakeContext{
		state: &state,
		cfg:   &dtlsconfig.HandshakeConfig{},
	})
	conn := &postHandshakeAlertConn{}

	err := post.handlePostHandshakeMessage(context.Background(), conn, &handshake.Handshake{
		Message: &handshake.MessageFinished{},
	}, 0)
	require.NoError(t, err)
	assert.Equal(t, []postHandshakeAlert{{
		level:       alert.Fatal,
		description: alert.UnexpectedMessage,
	}}, conn.notifications)
}

func TestServerRejectsNewSessionTicketWithAlert(t *testing.T) {
	state := dtlsstate.NewState13(false)
	post := newPostHandshake(handshakeContext{
		state: &state,
		cfg:   &dtlsconfig.HandshakeConfig{},
	})
	conn := &postHandshakeAlertConn{}

	err := post.handleNewSessionTicket(
		context.Background(),
		conn,
		&handshake.MessageNewSessionTicket{},
	)
	require.NoError(t, err)
	assert.Equal(t, []postHandshakeAlert{{
		level:       alert.Fatal,
		description: alert.UnexpectedMessage,
	}}, conn.notifications)
	assert.Zero(t, state.HandshakeRecvSequence)
}

func TestNewSessionTicketLifetimeLimit(t *testing.T) {
	state := dtlsstate.NewState13(true)
	post := newPostHandshake(handshakeContext{
		state: &state,
		cfg:   &dtlsconfig.HandshakeConfig{},
	})
	conn := &postHandshakeAlertConn{}

	err := post.handleNewSessionTicket(context.Background(), conn, &handshake.MessageNewSessionTicket{
		TicketLifetime: maxSessionTicketLifetime + 1,
	})
	require.NoError(t, err)
	assert.Equal(t, []postHandshakeAlert{{
		level:       alert.Fatal,
		description: alert.IllegalParameter,
	}}, conn.notifications)
	assert.Zero(t, state.HandshakeRecvSequence)
}

func TestPrepareNewSessionTicket(t *testing.T) {
	state := dtlsstate.NewState13(false)
	post := newPostHandshake(handshakeContext{
		state: &state,
		cfg:   &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second},
	})

	first, err := post.prepareNewSessionTicket(false)
	require.NoError(t, err)
	second, err := post.prepareNewSessionTicket(false)
	require.NoError(t, err)
	firstHandshake, ok := first.Packets[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	firstMessage, ok := firstHandshake.Message.(*handshake.MessageNewSessionTicket)
	require.True(t, ok)
	secondHandshake, ok := second.Packets[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	secondMessage, ok := secondHandshake.Message.(*handshake.MessageNewSessionTicket)
	require.True(t, ok)
	assert.Len(t, firstMessage.Ticket, 32)
	assert.NotEqual(t, firstMessage.Ticket, secondMessage.Ticket)
	assert.NotEqual(t, firstMessage.TicketNonce, secondMessage.TicketNonce)
}

func TestKeyUpdateCommitsWriteKeysOnlyAfterACK(t *testing.T) {
	state := newPostHandshakeKeyUpdateTestState(t, true)
	state.HandshakeSendSequence = 9
	post := newPostHandshake(handshakeContext{
		state: state,
		cfg:   &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second},
	})
	record := protocol.RecordNumber{Epoch: uint64(dtlsflight13.EpochApplication), SequenceNumber: 4}
	fragment := SentHandshakeFragment{MessageSequence: 9, Length: 1}
	conn := &postHandshakeKeyUpdateConn{
		state: state,
		result: &WriteResult{TrackedRecords: []SentHandshakeRecord{{
			Number: record, Fragments: []SentHandshakeFragment{fragment},
		}}},
	}
	completion, completionCtx := newPostHandshakeCompletion()

	require.NoError(t, post.startKeyUpdate(context.Background(), conn, postHandshakeCommand{
		Kind: commandSendKeyUpdate,
		KeyUpdate: keyUpdateCommand{
			Request: handshake.KeyUpdateRequested,
		},
		Completion: completion,
	}))
	require.Len(t, conn.writtenPackets, 1)
	packet := conn.writtenPackets[0]
	assert.Equal(t, dtlsflight13.EpochApplication, packet.Epoch)
	wireHandshake, ok := packet.Content.(*handshake.Handshake)
	require.True(t, ok)
	wireKeyUpdate, ok := wireHandshake.Message.(*handshake.MessageKeyUpdate)
	require.True(t, ok)
	assert.Equal(t, handshake.KeyUpdateRequested, wireKeyUpdate.RequestUpdate)
	assert.Equal(t, uint16(9), wireHandshake.Header.MessageSequence)
	assert.True(t, packet.TrackACK)
	assert.Equal(t, dtlsflight13.EpochApplication, state.LocalEpoch())
	current, ok := state.TrafficKeys.CurrentWrite()
	require.True(t, ok)
	assert.Equal(t, uint64(0), current.Generation)

	completed := post.applyACK(protocol.ACK{Records: []protocol.RecordNumber{record}})
	require.Equal(t, []postHandshakeFlightID{{
		Category: postHandshakeKeyUpdate, MessageSequence: 9,
	}}, completed)
	require.NoError(t, post.completePostHandshakeFlight(conn, completed[0]))
	assert.Equal(t, dtlsflight13.EpochApplication+1, state.LocalEpoch())
	current, ok = state.TrafficKeys.CurrentWrite()
	require.True(t, ok)
	assert.Equal(t, uint64(1), current.Generation)
	assert.Same(t, current, conn.committed)
	<-completionCtx.Done()
	assert.NoError(t, completion.result())
}

func TestBuildKeyUpdateFlightRejectsEpochOverflow(t *testing.T) {
	state := newPostHandshakeKeyUpdateTestState(t, true)
	current, ok := state.TrafficKeys.CurrentWrite()
	require.True(t, ok)
	state.TrafficKeys.Install(&dtlsstate.TrafficGeneration{
		Epoch:      ^uint16(0),
		Generation: current.Generation,
		Secret:     current.Secret,
		Protection: current.Protection,
	}, nil)
	state.SetLocalEpoch(^uint16(0))
	post := newPostHandshake(handshakeContext{state: state, cfg: &dtlsconfig.HandshakeConfig{}})

	_, err := post.buildKeyUpdateFlight(handshake.KeyUpdateNotRequested, nil)
	assert.ErrorIs(t, err, dtlserrors.ErrEpochOverflow)
}

func TestRequestedKeyUpdateInstallsReadKeysAndQueuesResponse(t *testing.T) {
	state := newPostHandshakeKeyUpdateTestState(t, false)
	state.HandshakeRecvSequence = 7
	state.HandshakeSendSequence = 11
	post := newPostHandshake(handshakeContext{
		state: state,
		cfg:   &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second},
	})
	conn := &postHandshakeKeyUpdateConn{state: state}

	require.NoError(t, post.handleKeyUpdate(
		context.Background(), conn,
		&handshake.MessageKeyUpdate{RequestUpdate: handshake.KeyUpdateRequested},
		dtlsflight13.EpochApplication,
	))
	assert.Equal(t, 8, state.HandshakeRecvSequence)
	assert.Equal(t, dtlsflight13.EpochApplication+1, state.RemoteEpoch())
	currentRead, ok := state.TrafficKeys.CurrentRead()
	require.True(t, ok)
	assert.Equal(t, uint64(1), currentRead.Generation)
	_, oldReadRetained := state.TrafficKeys.Read(dtlsflight13.EpochApplication)
	assert.True(t, oldReadRetained)
	require.Len(t, post.queue, 1)
	assert.Equal(t, handshake.KeyUpdateNotRequested, post.queue[0].KeyUpdate.Request)

	require.NoError(t, post.startQueuedPostHandshake(context.Background(), conn))
	require.Len(t, conn.writtenPackets, 1)
	responseHandshake, ok := conn.writtenPackets[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	response, ok := responseHandshake.Message.(*handshake.MessageKeyUpdate)
	require.True(t, ok)
	assert.Equal(t, handshake.KeyUpdateNotRequested, response.RequestUpdate)
	assert.Equal(t, dtlsflight13.EpochApplication, conn.writtenPackets[0].Epoch)
	assert.Equal(t, dtlsflight13.EpochApplication, state.LocalEpoch())
}

func TestRequiredKeyUpdateResponsesAreSerialized(t *testing.T) {
	state := newPostHandshakeKeyUpdateTestState(t, false)
	post := newPostHandshake(handshakeContext{
		state: state,
		cfg:   &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second},
	})
	conn := &postHandshakeKeyUpdateConn{state: state}
	request := &handshake.MessageKeyUpdate{RequestUpdate: handshake.KeyUpdateRequested}

	require.NoError(t, post.handleKeyUpdate(
		context.Background(), conn, request, dtlsflight13.EpochApplication,
	))
	require.NoError(t, post.handleKeyUpdate(
		context.Background(), conn, request, dtlsflight13.EpochApplication+1,
	))
	require.Len(t, post.queue, 2)

	require.NoError(t, post.startQueuedPostHandshake(context.Background(), conn))
	require.Len(t, post.queue, 1)
	require.Len(t, conn.writtenPackets, 1)
	require.Len(t, post.flights, 1)
	for id := range post.flights {
		require.NoError(t, post.completePostHandshakeFlight(conn, id))
	}

	require.NoError(t, post.startQueuedPostHandshake(context.Background(), conn))
	assert.Empty(t, post.queue)
	assert.Len(t, conn.writtenPackets, 2)
}

func TestApplicationDataChangesEpochOnlyAfterKeyUpdateACK(t *testing.T) {
	state := newPostHandshakeKeyUpdateTestState(t, false)
	post := newPostHandshake(handshakeContext{
		state: state,
		cfg:   &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second},
	})
	record := protocol.RecordNumber{Epoch: uint64(dtlsflight13.EpochApplication), SequenceNumber: 4}
	conn := &postHandshakeKeyUpdateConn{
		state: state,
		result: &WriteResult{TrackedRecords: []SentHandshakeRecord{{
			Number: record,
			Fragments: []SentHandshakeFragment{{
				MessageSequence: 0,
				Length:          1,
			}},
		}}},
	}
	applicationPacket := &dtlsflight.Outbound{
		Content:    &protocol.ApplicationData{Data: []byte("after update")},
		Protection: dtlsflight.ProtectionCiphertext,
	}
	post.queue = append(post.queue, postHandshakeCommand{
		Kind:    commandSendApplicationData,
		Packets: []*dtlsflight.Outbound{applicationPacket},
		Write: func(conn Conn, packets []*dtlsflight.Outbound) error {
			_, err := conn.WritePackets(context.Background(), packets)

			return err
		},
	})
	post.queueRequiredKeyUpdateResponse(handshake.KeyUpdateRequested)

	require.NoError(t, post.startQueuedPostHandshake(context.Background(), conn))
	require.Len(t, conn.writtenPackets, 2)
	_, isKeyUpdate := conn.writtenPackets[0].Content.(*handshake.Handshake)
	assert.True(t, isKeyUpdate)
	_, isApplicationData := conn.writtenPackets[1].Content.(*protocol.ApplicationData)
	assert.True(t, isApplicationData)
	assert.Equal(t, dtlsflight13.EpochApplication, applicationPacket.Epoch)
	assert.Empty(t, post.queue)

	completed := post.applyACK(protocol.ACK{Records: []protocol.RecordNumber{record}})
	require.Len(t, completed, 1)
	require.NoError(t, post.completePostHandshakeFlight(conn, completed[0]))
	afterACKPacket := &dtlsflight.Outbound{
		Content:    &protocol.ApplicationData{Data: []byte("after ACK")},
		Protection: dtlsflight.ProtectionCiphertext,
	}
	post.queue = append(post.queue, postHandshakeCommand{
		Kind:    commandSendApplicationData,
		Packets: []*dtlsflight.Outbound{afterACKPacket},
		Write: func(conn Conn, packets []*dtlsflight.Outbound) error {
			_, err := conn.WritePackets(context.Background(), packets)

			return err
		},
	})
	require.NoError(t, post.startQueuedPostHandshake(context.Background(), conn))
	require.Len(t, conn.writtenPackets, 3)
	assert.Equal(t, dtlsflight13.EpochApplication+1, afterACKPacket.Epoch)
}

func TestApplicationDataDoesNotWaitForNewSessionTicketACK(t *testing.T) {
	state := dtlsstate.NewState13(false)
	state.SetLocalEpoch(dtlsflight13.EpochApplication)
	post := newPostHandshake(handshakeContext{
		state: &state,
		cfg:   &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second},
	})
	applicationPacket := &dtlsflight.Outbound{
		Content:    &protocol.ApplicationData{Data: []byte("after ticket")},
		Protection: dtlsflight.ProtectionCiphertext,
	}
	post.queue = append(post.queue,
		postHandshakeCommand{Kind: commandSendNewSessionTicket},
		postHandshakeCommand{
			Kind:    commandSendApplicationData,
			Packets: []*dtlsflight.Outbound{applicationPacket},
			Write: func(conn Conn, packets []*dtlsflight.Outbound) error {
				_, err := conn.WritePackets(context.Background(), packets)

				return err
			},
		},
	)
	conn := &postHandshakeWriteConn{result: &WriteResult{}}

	require.NoError(t, post.startQueuedPostHandshake(context.Background(), conn))
	assert.Empty(t, post.queue)
	require.Len(t, post.flights, 1)
	require.Len(t, conn.writtenPackets, 2)
	_, isTicket := conn.writtenPackets[0].Content.(*handshake.Handshake)
	assert.True(t, isTicket)
	_, isApplicationData := conn.writtenPackets[1].Content.(*protocol.ApplicationData)
	assert.True(t, isApplicationData)
	assert.Equal(t, dtlsflight13.EpochApplication, applicationPacket.Epoch)
}

func TestRetransmittedKeyUpdateDoesNotRatchetReadKeysTwice(t *testing.T) {
	const messageSequence = uint16(5)
	state := newPostHandshakeKeyUpdateTestState(t, true)
	state.HandshakeRecvSequence = int(messageSequence)
	wire, err := (&handshake.Handshake{
		Header: handshake.Header{
			Type:            handshake.TypeKeyUpdate,
			MessageSequence: messageSequence,
		},
		Message: &handshake.MessageKeyUpdate{RequestUpdate: handshake.KeyUpdateNotRequested},
	}).Marshal()
	require.NoError(t, err)
	cache := dtlsflight.NewCache()
	cache.Push(wire, dtlsflight13.EpochApplication, messageSequence, handshake.TypeKeyUpdate, false)
	post := newPostHandshake(handshakeContext{
		state: state,
		cache: cache,
		cfg:   &dtlsconfig.HandshakeConfig{InitialRetransmitInterval: time.Second},
	})
	conn := &postHandshakeKeyUpdateConn{state: state}
	record := protocol.RecordNumber{Epoch: uint64(dtlsflight13.EpochApplication), SequenceNumber: 3}
	receive := func() error {
		return post.handlePostHandshakeReceive(context.Background(), conn, RecvHandshakeState{
			HasHandshake: true,
			RecordsToACK: []protocol.RecordNumber{record},
		})
	}

	require.NoError(t, receive())
	require.NoError(t, receive())
	assert.Equal(t, int(messageSequence)+1, state.HandshakeRecvSequence)
	currentRead, ok := state.TrafficKeys.CurrentRead()
	require.True(t, ok)
	assert.Equal(t, uint64(1), currentRead.Generation)
	assert.Len(t, conn.writtenPackets, 2, "both copies must be acknowledged")
}

func TestInvalidKeyUpdateUsesIllegalParameterAlert(t *testing.T) {
	state := newPostHandshakeKeyUpdateTestState(t, true)
	cache := dtlsflight.NewCache()
	header, err := (&handshake.Header{
		Type:           handshake.TypeKeyUpdate,
		Length:         1,
		FragmentLength: 1,
	}).Marshal()
	require.NoError(t, err)
	cache.Push(append(header, 2), dtlsflight13.EpochApplication, 0, handshake.TypeKeyUpdate, false)
	post := newPostHandshake(handshakeContext{state: state, cache: cache, cfg: &dtlsconfig.HandshakeConfig{}})
	conn := &postHandshakeAlertConn{}

	err = post.processPostHandshakeMessages(context.Background(), conn)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidKeyUpdate)
	assert.Equal(t, []postHandshakeAlert{{
		level: alert.Fatal, description: alert.IllegalParameter,
	}}, conn.notifications)
}
