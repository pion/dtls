// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"slices"
	"sync/atomic"
	"time"

	dtlsciphersuite "github.com/pion/dtls/v4/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

const (
	maxConnectionIDBatch = 8
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
	Epoch uint64

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
	// Required responses must be emitted before queued application writes.
	Required bool
}

type newConnectionIDCommand struct {
	NumCIDs uint8
	Usage   handshake.ConnectionIDUsage
}

type postHandshakeCommand struct {
	Kind postHandshakeCommandKind

	Packets         []*dtlsflight.Outbound
	Write           func(Conn, []*dtlsflight.Outbound) error
	KeyUpdate       keyUpdateCommand
	NewConnectionID newConnectionIDCommand
	Canceled        <-chan struct{}

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

type connectionIDConn interface {
	ReserveLocalCIDs([][]byte) ([][]byte, error)
	RemoveLocalCIDs([][]byte)
	CommitPeerConnectionIDs(*handshake.MessageNewConnectionID) error
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
	return &postHandshake{commands: make(chan postHandshakeCommand), flights: make(map[postHandshakeFlightID]*reliablePostHandshakeFlight), recordIndex: make(map[protocol.RecordNumber]postHandshakeRecord), initialRetransmitInterval: ctx.cfg.InitialRetransmitInterval, handshakeContext: ctx}
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
	applicationBlocked := false
	for i := 0; i < len(p.queue); {
		command := p.queue[i]
		if err, canceled := canceledPostHandshakeCommand(command); canceled {
			p.queue = slices.Delete(p.queue, i, i+1)
			command.Completion.complete(err)

			continue
		}
		if !p.commandEligible(command.Kind, applicationBlocked) {
			applicationBlocked = applicationBlocked || command.KeyUpdate.Required
			i++

			continue
		}
		p.queue = slices.Delete(p.queue, i, i+1)

		err := p.startPostHandshakeCommand(ctx, conn, command)
		if err != nil {
			command.Completion.complete(err)

			return err
		}
	}

	return nil
}

func (p *postHandshake) commandEligible(kind postHandshakeCommandKind, applicationBlocked bool) bool {
	var category postHandshakeCategory
	switch kind {
	case commandSendKeyUpdate:
		category = postHandshakeKeyUpdate
	case commandSendNewConnectionID:
		category = postHandshakeNewConnectionID
	case commandSendRequestConnectionID:
		category = postHandshakeRequestConnectionID
	case commandSendApplicationData:
		return !applicationBlocked
	default:
		// tickets may overlap, and invalid commands must reach validation.
		return true
	}
	for id := range p.flights {
		if id.Category == category {
			return false
		}
	}

	return true
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
	if err := p.validatePostHandshakeCommand(command); err != nil {
		return rejectPostHandshakeCommand(command, err)
	}
	switch command.Kind {
	case commandSendNewSessionTicket:
		return p.startNewSessionTicket(ctx, conn, false)
	case commandSendKeyUpdate:
		return p.startKeyUpdate(ctx, conn, command)
	case commandSendNewConnectionID:
		return p.startNewConnectionID(ctx, conn, command)
	case commandSendRequestConnectionID:
		return dtlserrors.ErrNotImplemented
	case commandSendApplicationData:
		return p.writeApplicationData(conn, command)
	default:
		return dtlserrors.ErrUnexpectedPostHandshakeMessage
	}
}

func rejectPostHandshakeCommand(command postHandshakeCommand, err error) error {
	if command.Completion == nil {
		return err
	}
	command.Completion.complete(err)

	return nil
}

// Reject local arguments before mutating sequence, key, or flight state.
func (p *postHandshake) validatePostHandshakeCommand(command postHandshakeCommand) error {
	switch command.Kind {
	case commandSendNewSessionTicket:
		if p.state.IsClient {
			return dtlserrors.ErrUnexpectedPostHandshakeMessage
		}
	case commandSendKeyUpdate:
		if command.KeyUpdate.Request > handshake.KeyUpdateRequested {
			return dtlserrors.ErrInvalidKeyUpdate
		}
	case commandSendNewConnectionID:
		return p.validateNewConnectionIDCommand(command.NewConnectionID)
	case commandSendRequestConnectionID:
		return dtlserrors.ErrNotImplemented
	case commandSendApplicationData:
	default:
		return dtlserrors.ErrUnexpectedPostHandshakeMessage
	}

	return nil
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

func (p *postHandshake) registerTransmission(flight *reliablePostHandshakeFlight, records []SentHandshakeRecord, first bool) {
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

func (p *postHandshake) nextTimer() (dtlsconfig.Timer, <-chan time.Time) {
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
	timer := p.cfg.NewTimer(delay)

	return timer, timer.C()
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
			description := alert.DecodeError
			if errors.As(err, &dtlsAlert) {
				description = dtlsAlert.Description
			}
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

func (p *postHandshake) handlePostHandshakeMessage(ctx context.Context, conn Conn, message *handshake.Handshake, epoch uint64) error {
	switch body := message.Message.(type) {
	case *handshake.MessageNewSessionTicket:
		return p.handleNewSessionTicket(ctx, conn, body)
	case *handshake.MessageKeyUpdate:
		return p.handleKeyUpdate(ctx, conn, body, epoch)
	case *handshake.MessageNewConnectionID:
		return p.handleNewConnectionID(ctx, conn, body)
	default:
		return fatalPostHandshakeAlert(ctx, conn, alert.UnexpectedMessage)
	}
}

func (p *postHandshake) validateNewConnectionIDCommand(command newConnectionIDCommand) error {
	if !p.state.CID.Negotiated || !p.state.CID.Receive.CanSendNewConnectionID {
		return dtlserrors.ErrUnexpectedPostHandshakeMessage
	}
	if command.Usage > handshake.ConnectionIDSpare {
		return dtlserrors.ErrInvalidConnectionIDUsage
	}
	if command.NumCIDs == 0 && command.Usage == handshake.ConnectionIDImmediate {
		return dtlserrors.ErrInvalidCIDFormat
	}
	if command.NumCIDs > maxConnectionIDBatch || p.state.CID.Receive.IDs.Len()+int(command.NumCIDs) > dtlsstate.MaxConnectionIDs {
		return dtlserrors.ErrConnectionIDLimit
	}
	if command.NumCIDs != 0 && p.cfg.ConnectionIDGenerator == nil {
		return dtlserrors.ErrNilConnectionIDGenerator
	}

	return nil
}

func (p *postHandshake) prepareNewConnectionID(command newConnectionIDCommand) (*handshake.MessageNewConnectionID, error) {
	message := &handshake.MessageNewConnectionID{Usage: command.Usage}
	seen := make(map[string]bool, command.NumCIDs)
	for range command.NumCIDs {
		cid, err := p.cfg.GenerateConnectionID()
		if err != nil {
			return nil, err
		}
		if seen[string(cid)] || p.state.CID.Receive.IDs.Contains(cid) {
			return nil, dtlserrors.ErrInvalidCIDFormat
		}
		seen[string(cid)] = true
		message.CIDs = append(message.CIDs, bytes.Clone(cid))
	}

	return message, nil
}

func (p *postHandshake) startNewConnectionID(ctx context.Context, conn Conn, command postHandshakeCommand) error {
	cidConn, ok := conn.(connectionIDConn)
	if !ok {
		return rejectPostHandshakeCommand(command, dtlserrors.ErrNotImplemented)
	}
	if p.state.HandshakeSendSequence > math.MaxUint16 {
		return dtlserrors.ErrHandshakeSequenceOverflow
	}
	message, err := p.prepareNewConnectionID(command.NewConnectionID)
	if err != nil {
		return rejectPostHandshakeCommand(command, err)
	}
	// Complete all fallible preparation before reserving routes or a sequence.
	body, err := message.Marshal()
	if err != nil {
		return rejectPostHandshakeCommand(command, err)
	}
	added, err := cidConn.ReserveLocalCIDs(message.CIDs)
	if err != nil {
		return rejectPostHandshakeCommand(command, err)
	}
	if cancelErr, canceled := canceledPostHandshakeCommand(command); canceled {
		cidConn.RemoveLocalCIDs(added)

		return rejectPostHandshakeCommand(command, cancelErr)
	}
	flight := p.newReliableFlight(postHandshakeNewConnectionID, message, len(body))
	flight.Completion = command.Completion

	return p.startFlight(ctx, conn, flight)
}

// newReliableFlight consumes a sequence after the caller validates the message and sequence limit.
func (p *postHandshake) newReliableFlight(category postHandshakeCategory, message handshake.Message, length int) *reliablePostHandshakeFlight {
	sequence := uint16(p.state.HandshakeSendSequence) //nolint:gosec // caller checks overflow.
	p.state.HandshakeSendSequence++
	packet := &dtlsflight.Outbound{
		Epoch: p.state.LocalEpoch(), Protection: dtlsflight.ProtectionCiphertext, TrackACK: true,
		Content: &handshake.Handshake{
			Header: handshake.Header{
				Type: message.Type(), MessageSequence: sequence,
				Length: uint32(length), FragmentLength: uint32(length), //nolint:gosec
			},
			Message: message,
		},
	}

	return &reliablePostHandshakeFlight{
		ID:      postHandshakeFlightID{Category: category, MessageSequence: sequence},
		Packets: []*dtlsflight.Outbound{packet}, Epoch: packet.Epoch,
		PendingFragments: make(map[postHandshakeFragment]struct{}), SentRecords: make(map[protocol.RecordNumber]struct{}),
		RetransmitInterval: p.initialRetransmitInterval,
	}
}

func (p *postHandshake) handleNewConnectionID(ctx context.Context, conn Conn, message *handshake.MessageNewConnectionID) error {
	// Check the negotiated direction, because a late zero-length CID
	// can disable sending CIDs without undoing negotiation.
	switch {
	case !p.state.CID.Negotiated || len(p.state.RemoteConnectionID) == 0:
		return fatalPostHandshakeAlert(ctx, conn, alert.UnexpectedMessage)
	case message.Usage > handshake.ConnectionIDSpare,
		message.MarshalSize() == 0,
		message.Usage == handshake.ConnectionIDImmediate && len(message.CIDs) == 0:
		return fatalPostHandshakeAlert(ctx, conn, alert.IllegalParameter)
	}
	cidConn, ok := conn.(connectionIDConn)
	if !ok {
		return dtlserrors.ErrNotImplemented
	}
	if err := cidConn.CommitPeerConnectionIDs(message); err != nil {
		return err
	}
	p.state.HandshakeRecvSequence++

	return nil
}

func fatalPostHandshakeAlert(ctx context.Context, conn Conn, description alert.Description) error {
	if err := conn.Notify(ctx, alert.Fatal, description); err != nil {
		return err
	}

	return &alert.Alert{Level: alert.Fatal, Description: description}
}

func (p *postHandshake) handleKeyUpdate(ctx context.Context, conn Conn, message *handshake.MessageKeyUpdate, epoch uint64) error {
	if p.state.TrafficKeys == nil {
		return dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}
	current, ok := p.state.TrafficKeys.CurrentRead()
	if !ok || current.Protection == nil {
		return dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}
	if current.Epoch != epoch || p.state.RemoteEpoch() != epoch {
		return fatalPostHandshakeAlert(ctx, conn, alert.UnexpectedMessage)
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
	command := postHandshakeCommand{Kind: commandSendKeyUpdate, KeyUpdate: keyUpdateCommand{Request: handshake.KeyUpdateNotRequested, Required: true}}
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

func (p *postHandshake) handleNewSessionTicket(ctx context.Context, conn Conn, message *handshake.MessageNewSessionTicket) error {
	if !p.state.IsClient {
		return fatalPostHandshakeAlert(ctx, conn, alert.UnexpectedMessage)
	}
	if message.TicketLifetime > maxSessionTicketLifetime {
		return fatalPostHandshakeAlert(ctx, conn, alert.IllegalParameter)
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

	return p.startFlight(ctx, conn, flight)
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

	return p.startFlight(ctx, conn, flight)
}

func (p *postHandshake) startFlight(ctx context.Context, conn Conn, flight *reliablePostHandshakeFlight) error {
	result, err := conn.WritePackets(ctx, flight.Packets)
	if err != nil {
		return err
	}
	p.flights[flight.ID] = flight
	p.registerTransmission(flight, result.TrackedRecords, true)
	flight.NextRetransmit = time.Now().Add(flight.RetransmitInterval)

	return nil
}

func (p *postHandshake) buildKeyUpdateFlight(request handshake.KeyUpdateRequest, completion *postHandshakeCompletion) (*reliablePostHandshakeFlight, error) {
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

	flight := p.newReliableFlight(postHandshakeKeyUpdate, message, len(body))
	flight.Completion = completion
	flight.PendingWrite = next

	return flight, nil
}

func (p *postHandshake) nextTrafficGeneration(current *dtlsstate.TrafficGeneration) (*dtlsstate.TrafficGeneration, error) {
	if current.Epoch == math.MaxUint64 || current.Generation == math.MaxUint64 {
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

	return &dtlsstate.TrafficGeneration{Epoch: current.Epoch + 1, Generation: current.Generation + 1, Secret: nextSecret, Protection: nextProtection}, nil
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

	return p.makeReliableNewSessionTicket(&handshake.MessageNewSessionTicket{TicketLifetime: newSessionTicketLifetime, TicketAgeAdd: binary.BigEndian.Uint32(ageAdd[:]), TicketNonce: nonce[:], Ticket: identity})
}

func (p *postHandshake) makeReliableNewSessionTicket(message *handshake.MessageNewSessionTicket) (*reliablePostHandshakeFlight, error) {
	body, err := message.Marshal()
	if err != nil {
		return nil, err
	}
	if p.state.HandshakeSendSequence > math.MaxUint16 {
		return nil, dtlserrors.ErrHandshakeSequenceOverflow
	}

	return p.newReliableFlight(postHandshakeNewSessionTicket, message, len(body)), nil
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

func (p *postHandshake) retransmitPostHandshake(ctx context.Context, conn Conn, now time.Time, disableRetransmitBackoff bool) error {
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

func (p *postHandshake) retransmitPostHandshakeFlight(ctx context.Context, conn Conn, flight *reliablePostHandshakeFlight, now time.Time, disableRetransmitBackoff bool) error {
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
