// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/sha256"
	"errors"
	"hash"

	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

const tlsHandshakeHeaderLength13 = 4

var (
	errInvalidHandshakeTranscriptMessage = &protocol.InternalError{
		Err: errors.New("invalid DTLS 1.3 handshake transcript message"), //nolint:err113
	}
	errHandshakeTranscriptHashNotSelected = &protocol.InternalError{
		Err: errors.New("DTLS 1.3 handshake transcript hash is not selected"), //nolint:err113
	}
	errHandshakeTranscriptHashAlreadySelected = &protocol.InternalError{
		Err: errors.New("DTLS 1.3 handshake transcript hash is already selected"), //nolint:err113
	}
	errHandshakeTranscriptMessageChanged = &protocol.InternalError{
		Err: errors.New("DTLS 1.3 handshake transcript message changed during retransmission"), //nolint:err113
	}
	errHandshakeTranscriptHelloRetryRequestInvalid = &protocol.InternalError{
		Err: errors.New("invalid DTLS 1.3 HelloRetryRequest transcript transition"), //nolint:err113
	}
)

type transcriptSender13 uint8

const (
	transcriptClient13 transcriptSender13 = iota
	transcriptServer13
)

type transcriptMessageID13 struct {
	sender transcriptSender13
	seq    uint16
}

type seenTranscriptMessage13 struct {
	length      int
	fingerprint [sha256.Size]byte
}

type transcriptMessage13 struct {
	id  transcriptMessageID13
	typ handshake.Type
}

type handshakeTranscript13 struct {
	newHash func() hash.Hash
	h       hash.Hash

	pending    [][]byte
	transcript []byte
	seen       map[transcriptMessageID13]seenTranscriptMessage13
	order      []transcriptMessage13

	helloRetryApplied bool
}

func newHandshakeTranscript13() *handshakeTranscript13 {
	return &handshakeTranscript13{
		seen: make(map[transcriptMessageID13]seenTranscriptMessage13),
	}
}

func canonicalHandshake13(raw []byte) ([]byte, error) {
	if len(raw) < handshake.HeaderLength {
		return nil, errBufferTooSmall
	}

	var header handshake.Header
	if err := header.Unmarshal(raw); err != nil {
		return nil, err
	}

	if header.FragmentOffset != 0 ||
		header.FragmentLength != header.Length ||
		len(raw) != handshake.HeaderLength+int(header.Length) {
		return nil, errInvalidHandshakeTranscriptMessage
	}

	out := make([]byte, tlsHandshakeHeaderLength13+int(header.Length))
	copy(out[:tlsHandshakeHeaderLength13], raw[:tlsHandshakeHeaderLength13])
	copy(out[tlsHandshakeHeaderLength13:], raw[handshake.HeaderLength:])

	return out, nil
}

func (t *handshakeTranscript13) selectHash(newHash func() hash.Hash) error {
	if newHash == nil {
		return errHandshakeTranscriptHashNotSelected
	}
	if t.h != nil {
		return errHandshakeTranscriptHashAlreadySelected
	}

	h := newHash()
	if h == nil {
		return errHandshakeTranscriptHashNotSelected
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

func (t *handshakeTranscript13) appendCanonical(id transcriptMessageID13, message []byte) error {
	if err := validateCanonicalHandshake13(message); err != nil {
		return err
	}

	fingerprint := sha256.Sum256(message)
	if seen, ok := t.seen[id]; ok {
		if seen.length == len(message) && seen.fingerprint == fingerprint {
			return nil
		}

		return errHandshakeTranscriptMessageChanged
	}

	messageCopy := append([]byte(nil), message...)
	t.seen[id] = seenTranscriptMessage13{
		length:      len(messageCopy),
		fingerprint: fingerprint,
	}
	t.order = append(t.order, transcriptMessage13{
		id:  id,
		typ: handshake.Type(messageCopy[0]),
	})
	t.transcript = append(t.transcript, messageCopy...)

	if t.h == nil {
		t.pending = append(t.pending, messageCopy)

		return nil
	}

	_, err := t.h.Write(messageCopy)

	return err
}

func (t *handshakeTranscript13) sum() ([]byte, error) {
	if t.h == nil {
		return nil, errHandshakeTranscriptHashNotSelected
	}

	return t.h.Sum(nil), nil
}

func (t *handshakeTranscript13) sumWithSuffix(suffix []byte) ([]byte, error) {
	if t.h == nil {
		return nil, errHandshakeTranscriptHashNotSelected
	}

	h := t.newHash()
	if h == nil {
		return nil, errHandshakeTranscriptHashNotSelected
	}
	if _, err := h.Write(t.transcript); err != nil {
		return nil, err
	}
	if _, err := h.Write(suffix); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (t *handshakeTranscript13) applyHelloRetryRequest() error {
	if t.h == nil {
		return errHandshakeTranscriptHashNotSelected
	}
	if t.helloRetryApplied ||
		len(t.order) != 1 ||
		t.order[0].id.sender != transcriptClient13 ||
		t.order[0].typ != handshake.TypeClientHello {
		return errHandshakeTranscriptHelloRetryRequestInvalid
	}

	clientHelloDigest := t.h.Sum(nil)
	messageHash := make([]byte, tlsHandshakeHeaderLength13+len(clientHelloDigest))
	messageHash[0] = byte(handshake.TypeMessageHash)
	util.PutBigEndianUint24(messageHash[1:], uint32(len(clientHelloDigest))) //nolint:gosec // G115
	copy(messageHash[tlsHandshakeHeaderLength13:], clientHelloDigest)

	h := t.newHash()
	if h == nil {
		return errHandshakeTranscriptHashNotSelected
	}
	if _, err := h.Write(messageHash); err != nil {
		return err
	}
	t.h = h
	t.transcript = append(t.transcript[:0], messageHash...)
	t.helloRetryApplied = true

	return nil
}

func validateCanonicalHandshake13(message []byte) error {
	if len(message) < tlsHandshakeHeaderLength13 {
		return errBufferTooSmall
	}
	if int(util.BigEndianUint24(message[1:])) != len(message)-tlsHandshakeHeaderLength13 {
		return errInvalidHandshakeTranscriptMessage
	}

	return nil
}
