// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/sha256"
	"hash"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

const tlsHandshakeHeaderLength13 = 4

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

	out := make([]byte, tlsHandshakeHeaderLength13+int(header.Length))
	copy(out[:tlsHandshakeHeaderLength13], raw[:tlsHandshakeHeaderLength13])
	copy(out[tlsHandshakeHeaderLength13:], raw[handshake.HeaderLength:])

	return out, nil
}

func (t *handshakeTranscript13) selectHash(newHash func() hash.Hash) error {
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

func (t *handshakeTranscript13) appendCanonical(id transcriptMessageID13, message []byte) error {
	if err := validateCanonicalHandshake13(message); err != nil {
		return err
	}

	fingerprint := sha256.Sum256(message)
	if seen, ok := t.seen[id]; ok {
		if seen.length == len(message) && seen.fingerprint == fingerprint {
			return nil
		}

		return dtlserrors.ErrHandshakeTranscriptMessageChanged
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
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	return t.h.Sum(nil), nil
}

func (t *handshakeTranscript13) sumWithSuffix(suffix []byte) ([]byte, error) {
	if t.h == nil {
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

func (t *handshakeTranscript13) applyHelloRetryRequest() error {
	if t.h == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if t.helloRetryApplied ||
		len(t.order) != 1 ||
		t.order[0].id.sender != transcriptClient13 ||
		t.order[0].typ != handshake.TypeClientHello {
		return dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid
	}

	clientHelloDigest := t.h.Sum(nil)
	messageHash := make([]byte, tlsHandshakeHeaderLength13+len(clientHelloDigest))
	messageHash[0] = byte(handshake.TypeMessageHash)
	util.PutBigEndianUint24(messageHash[1:], uint32(len(clientHelloDigest))) //nolint:gosec // G115
	copy(messageHash[tlsHandshakeHeaderLength13:], clientHelloDigest)

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

func validateCanonicalHandshake13(message []byte) error {
	if len(message) < tlsHandshakeHeaderLength13 {
		return dtlserrors.ErrBufferTooSmall
	}
	if int(util.BigEndianUint24(message[1:])) != len(message)-tlsHandshakeHeaderLength13 {
		return dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	return nil
}
