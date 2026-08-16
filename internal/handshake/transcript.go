// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package dtlshandshake contains DTLS handshake FSM, transcript, and key schedule helpers.
package dtlshandshake

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"hash"
	"maps"
	"slices"

	"github.com/pion/dtls/v3/internal/ciphersuite/types"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// tlsHandshakeHeaderLength is the TLS 1.3 transcript handshake header length.
const tlsHandshakeHeaderLength = 4

// transcriptSender identifies which side sent a transcript message.
type transcriptSender uint8

const (
	// transcriptSenderClient identifies client-sent transcript messages.
	transcriptSenderClient transcriptSender = iota
	// transcriptSenderServer identifies server-sent transcript messages.
	transcriptSenderServer
)

// transcriptMessageID is the retransmission-stable identity of a handshake message.
type transcriptMessageID struct {
	sender transcriptSender
	Seq    uint16
}

type seenTranscriptMessage struct {
	length      int
	fingerprint [sha256.Size]byte
}

// transcriptMessage records the transcript order for tests and diagnostics.
type transcriptMessage struct {
	ID   transcriptMessageID
	Type handshake.Type
}

// Transcript tracks DTLS 1.3 canonical handshake transcript bytes.
type Transcript struct {
	newHash func() hash.Hash
	h       hash.Hash

	pending    [][]byte
	transcript []byte
	seen       map[transcriptMessageID]seenTranscriptMessage
	order      []transcriptMessage

	helloRetryApplied bool
}

// NewTranscript returns an empty DTLS 1.3 handshake transcript.
func NewTranscript() *Transcript {
	return &Transcript{
		seen: make(map[transcriptMessageID]seenTranscriptMessage),
	}
}

// canonicalHandshake converts a DTLS handshake message to the TLS 1.3
// transcript form by dropping DTLS message_seq and fragmentation fields.
func canonicalHandshake(raw []byte) ([]byte, error) {
	if len(raw) < handshake.HeaderLength {
		return nil, dtlserrors.ErrBufferTooSmall
	}

	var header handshake.Header
	if err := header.Unmarshal(raw); err != nil {
		return nil, err
	}

	if header.FragmentOffset != 0 ||
		header.FragmentLength != header.Length ||
		len(raw) != handshake.HeaderLength+int(header.Length) {
		return nil, dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	out := make([]byte, tlsHandshakeHeaderLength+int(header.Length))
	copy(out[:tlsHandshakeHeaderLength], raw[:tlsHandshakeHeaderLength])
	copy(out[tlsHandshakeHeaderLength:], raw[handshake.HeaderLength:])

	return out, nil
}

// selectHash selects and initializes the transcript hash.
func (t *Transcript) selectHash(newHash func() hash.Hash) error {
	if newHash == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if t.h != nil {
		return dtlserrors.ErrHandshakeTranscriptHashAlreadySelected
	}

	h := newHash()
	if h == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	for _, message := range t.pending {
		if _, err := h.Write(message); err != nil {
			return err
		}
	}
	t.newHash = newHash
	t.h = h
	t.pending = nil

	return nil
}

// appendCanonical appends a canonical transcript handshake message.
func (t *Transcript) appendCanonical(id transcriptMessageID, message []byte) error {
	if err := validateCanonicalHandshake(message); err != nil {
		return err
	}

	fingerprint := sha256.Sum256(message)
	if seen, ok := t.seen[id]; ok {
		if seen.length == len(message) && seen.fingerprint == fingerprint {
			return nil
		}

		return dtlserrors.ErrHandshakeTranscriptMessageChanged
	}

	messageCopy := bytes.Clone(message)
	t.seen[id] = seenTranscriptMessage{
		length:      len(messageCopy),
		fingerprint: fingerprint,
	}
	t.order = append(t.order, transcriptMessage{
		ID:   id,
		Type: handshake.Type(messageCopy[0]),
	})
	t.transcript = append(t.transcript, messageCopy...)

	if t.h == nil {
		t.pending = append(t.pending, messageCopy)

		return nil
	}

	_, err := t.h.Write(messageCopy)

	return err
}

// SnapshotHash returns the transcript hash for all messages committed so far.
//
// CertificateVerify and Finished verification must call this before committing
// the message being verified.
func (t *Transcript) SnapshotHash() ([]byte, error) {
	if t == nil || t.h == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	return t.h.Sum(nil), nil
}

// SnapshotHashWithSuffix returns the transcript hash with suffix appended,
// without mutating the transcript.
func (t *Transcript) SnapshotHashWithSuffix(suffix []byte) ([]byte, error) {
	if t == nil || t.h == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	h := t.newHash()
	if h == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if _, err := h.Write(t.transcript); err != nil {
		return nil, err
	}
	if _, err := h.Write(suffix); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (t *Transcript) hasInitialClientHello() bool {
	return len(t.order) == 1 &&
		t.order[0].ID.sender == transcriptSenderClient &&
		t.order[0].Type == handshake.TypeClientHello
}

// applyHelloRetryRequest replaces the first ClientHello transcript with its
// synthetic message_hash, as required by TLS 1.3 HRR processing.
func (t *Transcript) applyHelloRetryRequest() error {
	if t.h == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if t.helloRetryApplied || !t.hasInitialClientHello() {
		return dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid
	}

	clientHelloDigest := t.h.Sum(nil)
	messageHash := make([]byte, tlsHandshakeHeaderLength+len(clientHelloDigest))
	messageHash[0] = byte(handshake.TypeMessageHash)
	util.PutBigEndianUint24(messageHash[1:], uint32(len(clientHelloDigest))) //nolint:gosec // G115
	copy(messageHash[tlsHandshakeHeaderLength:], clientHelloDigest)

	h := t.newHash()
	if h == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if _, err := h.Write(messageHash); err != nil {
		return err
	}
	t.h = h
	t.transcript = append(t.transcript[:0], messageHash...)
	t.helloRetryApplied = true

	return nil
}

// validateCanonicalHandshake validates a TLS 1.3 canonical handshake message.
func validateCanonicalHandshake(message []byte) error {
	if len(message) < tlsHandshakeHeaderLength {
		return dtlserrors.ErrBufferTooSmall
	}
	if int(util.BigEndianUint24(message[1:])) != len(message)-tlsHandshakeHeaderLength {
		return dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	return nil
}

// selectHashIfReady selects the transcript hash from cipherSuite if both are
// available, and treats repeat selection as a no-op.
func selectHashIfReady(t *Transcript, cipherSuite interface{ HashFunc() func() hash.Hash }) error {
	if t == nil || cipherSuite == nil {
		return nil
	}

	err := t.selectHash(cipherSuite.HashFunc())
	if errors.Is(err, dtlserrors.ErrHandshakeTranscriptHashAlreadySelected) {
		return nil
	}

	return err
}

// hasCanonical reports whether id already exists in the transcript with the
// same canonical message bytes.
func (t *Transcript) hasCanonical(id transcriptMessageID, message []byte) (bool, error) {
	if err := validateCanonicalHandshake(message); err != nil {
		return false, err
	}

	seen, ok := t.seen[id]
	if !ok {
		return false, nil
	}

	fingerprint := sha256.Sum256(message)
	if seen.length == len(message) && seen.fingerprint == fingerprint {
		return true, nil
	}

	return false, dtlserrors.ErrHandshakeTranscriptMessageChanged
}

func (t *Transcript) clone() (*Transcript, error) {
	if t == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	out := &Transcript{
		newHash:           t.newHash,
		pending:           util.CloneByteSlices(t.pending),
		transcript:        bytes.Clone(t.transcript),
		seen:              make(map[transcriptMessageID]seenTranscriptMessage, len(t.seen)),
		order:             slices.Clone(t.order),
		helloRetryApplied: t.helloRetryApplied,
	}
	maps.Copy(out.seen, t.seen)
	if t.h == nil {
		return out, nil
	}

	if out.newHash == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	out.h = out.newHash()
	if out.h == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if _, err := out.h.Write(out.transcript); err != nil {
		return nil, err
	}
	out.pending = nil

	return out, nil
}

func (t *Transcript) replaceWith(src *Transcript) error {
	if t == nil || src == nil {
		return nil
	}

	clone, err := src.clone()
	if err != nil {
		return err
	}
	*t = *clone

	return nil
}

// Bytes returns the canonical transcript bytes.
func (t *Transcript) Bytes() []byte {
	return bytes.Clone(t.transcript)
}

// seedTranscriptFromInitialFlights imports the dual-stack ClientHello generated
// before the DTLS 1.3 FSM exists.
func seedTranscriptFromInitialFlights(
	state *dtlsstate.State13,
	transcript *Transcript,
	flights []*dtlsflight.Packet,
	retransmit bool,
) error {
	if !state.IsClient {
		return nil
	}

	appended, err := AppendClientHelloInitialFlights(transcript, flights)
	if err != nil {
		return err
	}
	if retransmit && !appended {
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
		seq, canonical, ok, err := canonicalClientHelloInitialFlight(p)
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

func canonicalClientHelloInitialFlight(p *dtlsflight.Packet) (uint16, []byte, bool, error) {
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

func transcriptSenderForSide(isClient bool) transcriptSender {
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

	sender := transcriptSenderForSide(isClient)
	for _, p := range pkts {
		handshakeMessage, canonical, ok, err := canonicalOutboundHandshake(p)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}

		if err := appendHandshake(
			transcript,
			sender,
			cipherSuite,
			handshakeMessage.Header.MessageSequence,
			handshakeMessage.Message,
			canonical,
		); err != nil {
			return err
		}
	}

	return nil
}

func canonicalOutboundHandshake(p *dtlsflight.Packet) (*handshake.Handshake, []byte, bool, error) {
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

	return appendHandshake(
		t,
		transcriptSenderForSide(isClient),
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
	items []dtlsflight.DecodedHandshakeCacheItem,
) error {
	if transcript == nil {
		return nil
	}

	for _, item := range items {
		if err := item.Validate(); err != nil {
			return err
		}
		if requiresExplicitAuthenticationBeforeTranscriptCommit(item.Raw.Typ) {
			return dtlserrors.ErrHandshakeTranscriptExplicitAuthenticationRequired
		}
		if err := appendParsedInboundHandshake(
			transcript,
			item.Raw.IsClient,
			cipherSuite,
			item.Parsed,
			item.Raw.Data,
		); err != nil {
			return err
		}
	}

	return nil
}

func requiresExplicitAuthenticationBeforeTranscriptCommit(typ handshake.Type) bool {
	return typ == handshake.TypeCertificateVerify || typ == handshake.TypeFinished
}

func appendHandshake(
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
