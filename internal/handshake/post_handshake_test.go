// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"
	"testing"
	"time"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
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

func (c *postHandshakeWriteConn) WritePackets(
	_ context.Context,
	pkts []*dtlsflight.Packet,
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
	assert.True(t, packet.ShouldEncrypt)
	assert.True(t, packet.ShouldTrackACK)
	assert.Equal(t, uint16(7), packet.Record.Header.Epoch)
	assert.Equal(t, uint16(12), flight.ID.MessageSequence)
	assert.Equal(t, 13, state.HandshakeSendSequence)

	wireHandshake, ok := packet.Record.Content.(*handshake.Handshake)
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
	require.NoError(t, post.retransmitNewSessionTicket(context.Background(), conn, flight, now, true))
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
		post.completePostHandshakeFlight(id)
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
	firstACK, ok := conn.writtenPackets[0].Record.Content.(*protocol.ACK)
	require.True(t, ok)
	assert.Equal(t, []protocol.RecordNumber{record}, firstACK.Records)

	require.NoError(t, receive())
	assert.Equal(t, int(ticketRecvSequence)+1, state.HandshakeRecvSequence)
	require.Len(t, conn.writtenPackets, 2)
	retransmitACK, ok := conn.writtenPackets[1].Record.Content.(*protocol.ACK)
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

func TestHandleUnexpectedPostHandshakeMessageAlert(t *testing.T) {
	state := dtlsstate.NewState13(true)
	post := newPostHandshake(handshakeContext{
		state: &state,
		cfg:   &dtlsconfig.HandshakeConfig{},
	})
	conn := &postHandshakeAlertConn{}

	err := post.handlePostHandshakeMessage(context.Background(), conn, &handshake.Handshake{
		Message: &handshake.MessageFinished{},
	})
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
	firstHandshake, ok := first.Packets[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	firstMessage, ok := firstHandshake.Message.(*handshake.MessageNewSessionTicket)
	require.True(t, ok)
	secondHandshake, ok := second.Packets[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	secondMessage, ok := secondHandshake.Message.(*handshake.MessageNewSessionTicket)
	require.True(t, ok)
	assert.Len(t, firstMessage.Ticket, 32)
	assert.NotEqual(t, firstMessage.Ticket, secondMessage.Ticket)
	assert.NotEqual(t, firstMessage.TicketNonce, secondMessage.TicketNonce)
}
