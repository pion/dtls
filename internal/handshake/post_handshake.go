// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync/atomic"
	"time"

	dtlsciphersuite "github.com/pion/dtls/v3/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

const (
	// Same value as BoringsSSL default.
	// https://boringssl.googlesource.com/boringssl/+/5b0508f29ec17a6a2d4780b3d2715a7feaa99d40/include/openssl/ssl.h#2251
	newSessionTicketLifetime = 2 * 24 * 60 * 60
	// ticket_lifetime:  Indicates the lifetime in seconds as a 32-bit
	// unsigned integer in network byte order from the time of ticket
	// issuance.  Servers MUST NOT use any value greater than
	// 604800 seconds (7 days).
	// https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.1
	maxSessionTicketLifetime = 7 * 24 * 60 * 60
)

// PostHandshake is the state machine for DTLS 1.3 post-handshake state.

// UpdateKeys()
// |
// v
// +---------------------------------------------------------------+
// |                    fsm13: StateFinished  / PostHandshake      |
// |                                                               |
// |  incoming control event     outgoing request      RTO timer   |
// |  ----------------------     ----------------      ---------   |
// |  NewSessionTicket           Send KeyUpdate        retransmit  |
// |  KeyUpdate                  Send ticket           active      |
// |  ACK                        response KeyUpdate    flight      |
// |                                                               |
// |                  one active outbound flight                   |
// |                  plus an outbound queue                       |
// +---------------------------------------------------------------+
//                              |                              |
//                              v                              v
//                       record/key state                writePackets()

type postHandshakeCategory uint8

// rfc9147 section 5.8.4
// https://datatracker.ietf.org/doc/html/rfc9147#section-5.8.4
const (
	postHandshakeNewSessionTicket     postHandshakeCategory = iota //nolint:unused
	postHandshakeKeyUpdate                                         //nolint:unused
	postHandshakeNewConnectionID                                   //nolint:unused
	postHandshakeRequestConnectionID                               //nolint:unused
	postHandshakeClientAuthentication                              //nolint:unused
)

type postHandshakeFlightID struct {
	Category        postHandshakeCategory
	MessageSequence uint16
}

type postHandshakeFragment struct {
	MessageSequence uint16
	Offset          uint32
	Length          uint32
}

type postHandshakeRecord struct {
	Flight    postHandshakeFlightID
	Fragments []postHandshakeFragment
}

type postHandshakeOutcome struct {
	err error
}

// postHandshakeCompletion publishes a one-shot operation result.
type postHandshakeCompletion struct {
	signal context.CancelFunc

	outcome atomic.Pointer[postHandshakeOutcome]
}

type reliablePostHandshakeFlight struct {
	ID postHandshakeFlightID

	// Constructed once. Retransmissions will reuse these messages and their
	// message_seq values.
	Packets []*dtlsflight.Outbound

	// All retransmissions will use this epoch/key generation.
	Epoch uint16

	// Logical fragments not yet acknowledged.
	PendingFragments map[postHandshakeFragment]struct{}

	// Every record number used by the transmission and all
	// retransmissions.
	SentRecords map[protocol.RecordNumber]struct{}

	RetransmitInterval time.Duration
	NextRetransmit     time.Time

	// non-nil for application commands that wait for completion.
	Completion *postHandshakeCompletion

	// non-nil only when acknowledging this flight commits a KeyUpdate.
	PendingWrite *dtlsstate.TrafficGeneration
}

type postHandshakeCommandKind uint8

const (
	commandSendNewSessionTicket postHandshakeCommandKind = iota
	commandSendKeyUpdate
	commandSendNewConnectionID
	commandSendRequestConnectionID
	commandSendApplicationData
)

type keyUpdateCommand struct {
	Request handshake.KeyUpdateRequest
}

type postHandshakeCommand struct {
	Kind postHandshakeCommandKind

	Packets   []*dtlsflight.Outbound
	Write     func(Conn, []*dtlsflight.Outbound) error
	KeyUpdate keyUpdateCommand
	Canceled  <-chan struct{}

	// non-nil for application commands that wait for completion.
	Completion *postHandshakeCompletion
}

type postHandshake struct {
	initialized     bool
	nextTicketNonce uint64

	commands chan postHandshakeCommand
	queue    []postHandshakeCommand

	flights map[postHandshakeFlightID]*reliablePostHandshakeFlight

	// Reverse lookup for received ACK record numbers.
	recordIndex map[protocol.RecordNumber]postHandshakeRecord

	initialRetransmitInterval time.Duration
	handshakeContext
}

type keyUpdateCommitConn interface {
	CommitLocalKeyUpdate(*dtlsstate.TrafficGeneration) error
}

type pendingACKConn interface {
	TakePendingACKs() []protocol.RecordNumber
}

func newPostHandshakeCompletion() (*postHandshakeCompletion, context.Context) {
	ctx, cancel := context.WithCancel(context.Background())

	return &postHandshakeCompletion{
		signal: cancel,
	}, ctx
}

func (c *postHandshakeCompletion) complete(err error) {
	if c == nil {
		return
	}
	if c.outcome.CompareAndSwap(nil, &postHandshakeOutcome{err: err}) {
		c.signal()
	}
}

// result must only be called after the paired completion context is done.
func (c *postHandshakeCompletion) result() error {
	return c.outcome.Load().err
}

func newPostHandshake(ctx handshakeContext) *postHandshake {
	return &postHandshake{
		commands: make(chan postHandshakeCommand),

		flights: make(
			map[postHandshakeFlightID]*reliablePostHandshakeFlight,
		),
		recordIndex: make(
			map[protocol.RecordNumber]postHandshakeRecord,
		),

		initialRetransmitInterval: ctx.cfg.InitialRetransmitInterval,
		handshakeContext:          ctx,
	}
}

func (p *postHandshake) initialize() {
	if p.initialized {
		return
	}
	p.initialized = true

	if !p.state.IsClient {
		p.queue = append(
			p.queue,
			postHandshakeCommand{
				Kind: commandSendNewSessionTicket,
			},
		)
	}
}

func (p *postHandshake) startQueuedPostHandshake(ctx context.Context, conn Conn) error {
	for len(p.queue) != 0 {
		// Reliable post-handshake messages use one active outbound flight.
		// Application records may follow a flight that has already been emitted.
		// For KeyUpdate they continue using the current generation until the ACK
		// commits the pending generation.
		if len(p.flights) != 0 && p.queue[0].Kind != commandSendApplicationData {
			return nil
		}
		command := p.queue[0]
		p.queue = p.queue[1:]
		if err, canceled := canceledPostHandshakeCommand(command); canceled {
			command.Completion.complete(err)

			continue
		}

		err := p.startPostHandshakeCommand(ctx, conn, command)
		if err != nil {
			command.Completion.complete(err)

			return err
		}
	}

	return nil
}

func canceledPostHandshakeCommand(command postHandshakeCommand) (error, bool) {
	if command.Canceled == nil {
		return nil, false
	}
	select {
	case <-command.Canceled:
		return context.Canceled, true
	default:
		return nil, false
	}
}

func (p *postHandshake) startPostHandshakeCommand(
	ctx context.Context,
	conn Conn,
	command postHandshakeCommand,
) error {
	switch command.Kind {
	case commandSendNewSessionTicket:
		return p.startNewSessionTicket(ctx, conn, false)
	case commandSendKeyUpdate:
		return p.startKeyUpdate(ctx, conn, command)
	case commandSendNewConnectionID,
		commandSendRequestConnectionID:
		return dtlserrors.ErrNotImplemented
	case commandSendApplicationData:
		return p.writeApplicationData(conn, command)
	default:
		return dtlserrors.ErrUnexpectedPostHandshakeMessage
	}
}

func (p *postHandshake) writeApplicationData(conn Conn, command postHandshakeCommand) error {
	for _, packet := range command.Packets {
		packet.Epoch = p.state.LocalEpoch()
	}
	err := command.Write(conn, command.Packets)
	command.Completion.complete(err)

	// Report application write failures to the caller without terminating the
	// post-handshake state machine. This preserves Conn.Write's behavior.
	return nil
}

func (p *postHandshake) applyACK(ack protocol.ACK) []postHandshakeFlightID {
	completed := map[postHandshakeFlightID]struct{}{}
	for _, number := range ack.Records {
		record, ok := p.recordIndex[number]
		if !ok {
			continue
		}

		flight := p.flights[record.Flight]
		if flight == nil {
			delete(p.recordIndex, number)

			continue
		}

		for _, fragment := range record.Fragments {
			delete(flight.PendingFragments, fragment)
		}
		delete(p.recordIndex, number)
		if len(flight.PendingFragments) == 0 {
			completed[flight.ID] = struct{}{}
		}
	}

	out := make([]postHandshakeFlightID, 0, len(completed))
	for id := range completed {
		out = append(out, id)
	}

	return out
}

func (p *postHandshake) registerTransmission(
	flight *reliablePostHandshakeFlight,
	records []SentHandshakeRecord,
	first bool,
) {
	for _, record := range records {
		fragments := make([]postHandshakeFragment, 0, len(record.Fragments))
		for _, sent := range record.Fragments {
			fragment := postHandshakeFragment(sent)
			fragments = append(fragments, fragment)
			if first {
				flight.PendingFragments[fragment] = struct{}{}
			}
		}

		flight.SentRecords[record.Number] = struct{}{}
		p.recordIndex[record.Number] = postHandshakeRecord{
			Flight:    flight.ID,
			Fragments: fragments,
		}
	}
}

func (p *postHandshake) nextTimer() (*time.Timer, <-chan time.Time) {
	var next time.Time
	for _, flight := range p.flights {
		if next.IsZero() || flight.NextRetransmit.Before(next) {
			next = flight.NextRetransmit
		}
	}
	if next.IsZero() {
		return nil, nil
	}

	delay := max(time.Until(next), 0)
	timer := time.NewTimer(delay)

	return timer, timer.C
}

func (p *postHandshake) handlePostHandshakeReceive(
	ctx context.Context,
	conn Conn,
	received RecvHandshakeState,
) error {
	for _, ack := range received.ACKs {
		for _, id := range p.applyACK(ack) {
			if err := p.completePostHandshakeFlight(conn, id); err != nil {
				return err
			}
		}
	}

	if received.HasHandshake {
		if err := p.processPostHandshakeMessages(ctx, conn); err != nil {
			return err
		}
	}
	if pendingConn, ok := conn.(pendingACKConn); ok {
		received.RecordsToACK = append(received.RecordsToACK, pendingConn.TakePendingACKs()...)
	}

	return sendACK(ctx, conn, p.state.LocalEpoch(), received.RecordsToACK)
}

func (p *postHandshake) processPostHandshakeMessages(ctx context.Context, conn Conn) error {
	for p.state.HandshakeRecvSequence <= math.MaxUint16 {
		item, ok := p.cache.PullExact(
			uint16(p.state.HandshakeRecvSequence), //nolint:gosec // bounded above
			!p.state.IsClient,
		)
		if !ok {
			return nil
		}

		message, err := p.cache.DecodeProtectedHandshakeItem(
			item,
			item.Typ,
			uint16(p.state.HandshakeRecvSequence), //nolint:gosec // bounded above
			func(data []byte) (*handshake.Handshake, error) {
				parsed := &handshake.Handshake{}
				if err := parsed.Unmarshal(data); err != nil {
					return nil, err
				}

				return parsed, nil
			},
		)
		if err != nil {
			var dtlsAlert *alert.Alert
			errors.As(err, &dtlsAlert)
			description := dtlsAlert.Description
			if errors.Is(err, dtlserrors.ErrInvalidKeyUpdate) {
				description = alert.IllegalParameter
			}
			if alertErr := conn.Notify(ctx, alert.Fatal, description); alertErr != nil {
				return alertErr
			}

			return err
		}
		if err := p.handlePostHandshakeMessage(ctx, conn, message, item.Epoch); err != nil {
			return err
		}
	}

	return dtlserrors.ErrHandshakeSequenceOverflow
}

func (p *postHandshake) handlePostHandshakeMessage(
	ctx context.Context,
	conn Conn,
	message *handshake.Handshake,
	epoch uint16,
) error {
	switch body := message.Message.(type) {
	case *handshake.MessageNewSessionTicket:
		return p.handleNewSessionTicket(ctx, conn, body)
	case *handshake.MessageKeyUpdate:
		return p.handleKeyUpdate(ctx, conn, body, epoch)
	default:
		return conn.Notify(ctx, alert.Fatal, alert.UnexpectedMessage)
	}
}

func (p *postHandshake) handleKeyUpdate(
	ctx context.Context,
	conn Conn,
	message *handshake.MessageKeyUpdate,
	epoch uint16,
) error {
	if p.state.TrafficKeys == nil {
		return dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}
	current, ok := p.state.TrafficKeys.CurrentRead()
	if !ok || current.Protection == nil {
		return dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}
	if current.Epoch != epoch || p.state.RemoteEpoch() != epoch {
		return conn.Notify(ctx, alert.Fatal, alert.UnexpectedMessage)
	}
	next, err := p.nextTrafficGeneration(current)
	if err != nil {
		return err
	}

	p.queueRequiredKeyUpdateResponse(message.RequestUpdate)

	p.state.TrafficKeys.Install(nil, next)
	p.state.SetRemoteEpoch(next.Epoch)
	p.state.HandshakeRecvSequence++

	return conn.HandleQueuedPackets(ctx)
}

func (p *postHandshake) queueRequiredKeyUpdateResponse(request handshake.KeyUpdateRequest) {
	if request != handshake.KeyUpdateRequested {
		return
	}
	command := postHandshakeCommand{
		Kind: commandSendKeyUpdate,
		KeyUpdate: keyUpdateCommand{
			Request: handshake.KeyUpdateNotRequested,
		},
	}
	insertAt := len(p.queue)
	for i, queued := range p.queue {
		if queued.Kind == commandSendApplicationData {
			insertAt = i

			break
		}
	}
	p.queue = append(p.queue, postHandshakeCommand{})
	copy(p.queue[insertAt+1:], p.queue[insertAt:])
	p.queue[insertAt] = command
}

func (p *postHandshake) handleNewSessionTicket(
	ctx context.Context,
	conn Conn,
	message *handshake.MessageNewSessionTicket,
) error {
	if !p.state.IsClient {
		return conn.Notify(ctx, alert.Fatal, alert.UnexpectedMessage)
	}
	if message.TicketLifetime > maxSessionTicketLifetime {
		return conn.Notify(ctx, alert.Fatal, alert.IllegalParameter)
	}

	// todo: ticket persistence and PSK derivation.
	// nolint:godox

	p.state.HandshakeRecvSequence++

	return nil
}

func (p *postHandshake) startNewSessionTicket(ctx context.Context, conn Conn, isClient bool) error {
	flight, err := p.prepareNewSessionTicket(isClient)
	if err != nil {
		return err
	}

	result, err := conn.WritePackets(ctx, flight.Packets)
	if err != nil {
		return err
	}
	p.flights[flight.ID] = flight
	p.registerTransmission(flight, result.TrackedRecords, true)
	flight.NextRetransmit = time.Now().Add(flight.RetransmitInterval)

	return nil
}

func (p *postHandshake) startKeyUpdate(
	ctx context.Context,
	conn Conn,
	command postHandshakeCommand,
) error {
	flight, err := p.buildKeyUpdateFlight(command.KeyUpdate.Request, command.Completion)
	if err != nil {
		return err
	}

	result, err := conn.WritePackets(ctx, flight.Packets)
	if err != nil {
		return err
	}
	p.flights[flight.ID] = flight
	p.registerTransmission(flight, result.TrackedRecords, true)
	flight.NextRetransmit = time.Now().Add(flight.RetransmitInterval)

	return nil
}

func (p *postHandshake) buildKeyUpdateFlight(
	request handshake.KeyUpdateRequest,
	completion *postHandshakeCompletion,
) (*reliablePostHandshakeFlight, error) {
	if p.state.TrafficKeys == nil {
		return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}
	current, ok := p.state.TrafficKeys.CurrentWrite()
	if !ok || current.Protection == nil {
		return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}
	if current.Epoch != p.state.LocalEpoch() {
		return nil, dtlserrors.ErrInvalidEpoch
	}
	next, err := p.nextTrafficGeneration(current)
	if err != nil {
		return nil, err
	}

	message := &handshake.MessageKeyUpdate{RequestUpdate: request}
	body, err := message.Marshal()
	if err != nil {
		return nil, err
	}
	if p.state.HandshakeSendSequence > math.MaxUint16 {
		return nil, dtlserrors.ErrHandshakeSequenceOverflow
	}

	messageSequence := uint16(p.state.HandshakeSendSequence) //nolint:gosec // bounded above
	p.state.HandshakeSendSequence++
	packet := &dtlsflight.Outbound{
		Epoch: current.Epoch,
		Content: &handshake.Handshake{
			Header: handshake.Header{
				Type:            handshake.TypeKeyUpdate,
				Length:          uint32(len(body)), //nolint:gosec // marshal limits the message size
				MessageSequence: messageSequence,
				FragmentLength:  uint32(len(body)), //nolint:gosec // marshal limits the message size
			},
			Message: message,
		},
		Protection: dtlsflight.ProtectionCiphertext,
		TrackACK:   true,
	}
	id := postHandshakeFlightID{
		Category:        postHandshakeKeyUpdate,
		MessageSequence: messageSequence,
	}

	return &reliablePostHandshakeFlight{
		ID:                 id,
		Packets:            []*dtlsflight.Outbound{packet},
		Epoch:              current.Epoch,
		PendingFragments:   make(map[postHandshakeFragment]struct{}),
		SentRecords:        make(map[protocol.RecordNumber]struct{}),
		RetransmitInterval: p.initialRetransmitInterval,
		Completion:         completion,
		PendingWrite:       next,
	}, nil
}

func (p *postHandshake) nextTrafficGeneration(
	current *dtlsstate.TrafficGeneration,
) (*dtlsstate.TrafficGeneration, error) {
	if current.Epoch == math.MaxUint16 {
		return nil, dtlserrors.ErrEpochOverflow
	}
	cipherSuite, err := recordProtectionCipherSuite(p.state)
	if err != nil {
		return nil, err
	}
	nextSecret, err := deriveNextApplicationTrafficSecret(cipherSuite.HashFunc(), current.Secret)
	if err != nil {
		return nil, err
	}
	trafficSecret, err := dtlsciphersuite.NewTrafficSecret(nextSecret)
	if err != nil {
		return nil, err
	}
	nextProtection, err := cipherSuite.NewTrafficProtection(trafficSecret)
	if err != nil {
		return nil, err
	}
	if nextProtection == nil {
		return nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	return &dtlsstate.TrafficGeneration{
		Epoch:      current.Epoch + 1,
		Generation: current.Generation + 1,
		Secret:     nextSecret,
		Protection: nextProtection,
	}, nil
}

func (p *postHandshake) prepareNewSessionTicket(isClient bool) (*reliablePostHandshakeFlight, error) {
	if isClient {
		return nil, dtlserrors.ErrUnexpectedPostHandshakeMessage
	}

	identity := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, identity); err != nil {
		return nil, err
	}

	var ageAdd [4]byte
	if _, err := io.ReadFull(rand.Reader, ageAdd[:]); err != nil {
		return nil, err
	}

	var nonce [8]byte
	binary.BigEndian.PutUint64(nonce[:], p.nextTicketNonce)
	p.nextTicketNonce++

	return p.makeReliableNewSessionTicket(&handshake.MessageNewSessionTicket{
		TicketLifetime: newSessionTicketLifetime,
		TicketAgeAdd:   binary.BigEndian.Uint32(ageAdd[:]),
		TicketNonce:    nonce[:],
		Ticket:         identity,
	})
}

func (p *postHandshake) makeReliableNewSessionTicket(
	message *handshake.MessageNewSessionTicket,
) (*reliablePostHandshakeFlight, error) {
	body, err := message.Marshal()
	if err != nil {
		return nil, err
	}
	if p.state.HandshakeSendSequence > math.MaxUint16 {
		return nil, dtlserrors.ErrHandshakeSequenceOverflow
	}

	messageSequence := uint16(p.state.HandshakeSendSequence) //nolint:gosec // bounded above
	p.state.HandshakeSendSequence++
	packet := &dtlsflight.Outbound{
		Epoch: p.state.LocalEpoch(),
		Content: &handshake.Handshake{
			Header: handshake.Header{
				Type:            handshake.TypeNewSessionTicket,
				Length:          uint32(len(body)), //nolint:gosec // marshal limits the message size
				MessageSequence: messageSequence,
				FragmentLength:  uint32(len(body)), //nolint:gosec // marshal limits the message size
			},
			Message: message,
		},
		Protection: dtlsflight.ProtectionCiphertext,
		TrackACK:   true,
	}
	id := postHandshakeFlightID{
		Category:        postHandshakeNewSessionTicket,
		MessageSequence: messageSequence,
	}

	return &reliablePostHandshakeFlight{
		ID:                 id,
		Packets:            []*dtlsflight.Outbound{packet},
		Epoch:              p.state.LocalEpoch(),
		PendingFragments:   make(map[postHandshakeFragment]struct{}),
		SentRecords:        make(map[protocol.RecordNumber]struct{}),
		RetransmitInterval: p.initialRetransmitInterval,
	}, nil
}

func (p *postHandshake) completePostHandshakeFlight(conn Conn, id postHandshakeFlightID) error {
	flight := p.flights[id]
	if flight == nil {
		return nil
	}

	var completionErr error
	if flight.PendingWrite != nil {
		keyConn, ok := conn.(keyUpdateCommitConn)
		if !ok {
			completionErr = dtlserrors.ErrNotImplemented
		} else {
			completionErr = keyConn.CommitLocalKeyUpdate(flight.PendingWrite)
		}
	}
	for number := range flight.SentRecords {
		delete(p.recordIndex, number)
	}
	delete(p.flights, id)
	flight.Completion.complete(completionErr)

	return completionErr
}

func (p *postHandshake) fail(err error) {
	for _, command := range p.queue {
		command.Completion.complete(err)
	}
	p.queue = nil
	for id, flight := range p.flights {
		flight.Completion.complete(err)
		delete(p.flights, id)
	}
	p.recordIndex = make(map[protocol.RecordNumber]postHandshakeRecord)
}

func (p *postHandshake) retransmitPostHandshake(
	ctx context.Context,
	conn Conn,
	now time.Time,
	disableRetransmitBackoff bool,
) error {
	for _, flight := range p.flights {
		if flight.NextRetransmit.After(now) {
			continue
		}
		if err := p.retransmitPostHandshakeFlight(ctx, conn, flight, now, disableRetransmitBackoff); err != nil {
			return err
		}
	}

	return nil
}

func (p *postHandshake) retransmitPostHandshakeFlight(
	ctx context.Context,
	conn Conn,
	flight *reliablePostHandshakeFlight,
	now time.Time,
	disableRetransmitBackoff bool,
) error {
	for _, packet := range flight.Packets {
		message, ok := packet.Content.(*handshake.Handshake)
		if !ok {
			continue
		}
		packet.HandshakeFragmentOffsets = map[uint32]uint32{}
		for fragment := range flight.PendingFragments {
			if fragment.MessageSequence == message.Header.MessageSequence {
				packet.HandshakeFragmentOffsets[fragment.Offset] = fragment.Length
			}
		}
	}

	result, err := conn.WritePackets(ctx, flight.Packets)
	if err != nil {
		return err
	}
	p.registerTransmission(flight, result.TrackedRecords, false)
	if !disableRetransmitBackoff {
		flight.RetransmitInterval *= 2
		if flight.RetransmitInterval > 60*time.Second {
			flight.RetransmitInterval = 60 * time.Second
		}
	}
	flight.NextRetransmit = now.Add(flight.RetransmitInterval)

	return nil
}
