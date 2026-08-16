// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package flight contains shared internal flight state and helpers.
package flight

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

type Cache struct {
	cache []*HandshakeCacheItem
	mu    sync.Mutex
}

type handshakeCacheDecodeKind uint8

const (
	handshakeCacheDecodeGeneric handshakeCacheDecodeKind = iota
	handshakeCacheDecodeProtected13
)

type handshakeCacheDecodeContext struct {
	kind                 handshakeCacheDecodeKind
	keyExchangeAlgorithm ciphersuite.KeyExchangeAlgorithm
}

// HandshakeCacheDecoder decodes a complete cached handshake message.
type HandshakeCacheDecoder func([]byte) (*handshake.Handshake, error)

func NewCache() *Cache {
	return &Cache{}
}

func (h *Cache) Push(data []byte, epoch, messageSequence uint16, typ handshake.Type, isClient bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cache = append(h.cache, &HandshakeCacheItem{
		Data:            bytes.Clone(data),
		Epoch:           epoch,
		MessageSequence: messageSequence,
		Typ:             typ,
		IsClient:        isClient,
	})
}

// PullExact returns the handshake message with the requested sequence and
// sender.
func (h *Cache) PullExact(messageSequence uint16, isClient bool) (*HandshakeCacheItem, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, item := range h.cache {
		if item.MessageSequence == messageSequence && item.IsClient == isClient {
			return item, true
		}
	}

	return nil, false
}

// Pull returns a list handshakes that match the requested rules.
// The list will contain null entries for rules that can't be satisfied.
// Multiple entries may match a rule, but only the last match is returned (ie ClientHello with cookies).
func (h *Cache) Pull(rules ...HandshakeCachePullRule) []*HandshakeCacheItem {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]*HandshakeCacheItem, len(rules))
	for i, r := range rules {
		for _, c := range h.cache {
			if c.Typ == r.Typ && c.IsClient == r.IsClient && c.Epoch == r.Epoch {
				switch {
				case out[i] == nil:
					out[i] = c
				case out[i].MessageSequence < c.MessageSequence:
					out[i] = c
				}
			}
		}
	}

	return out
}

func (h *Cache) FullPullMapItems(
	startSeq int,
	cipherSuite dtlsconfig.CipherSuite,
	rules ...HandshakeCachePullRule,
) HandshakeCachePullResult {
	selection := h.PullSequential(startSeq, rules...)
	if selection.Err != nil || !selection.Ready {
		return HandshakeCachePullResult{
			NextSequence: startSeq,
			Ready:        selection.Ready,
			Err:          selection.Err,
		}
	}

	return h.fullPullMapCacheItems(startSeq, cipherSuite, rules, selection.Items)
}

// FullPullMapOneOfItems decodes exactly one of the allowed messages at
// startSeq. A different message from the same peer and epoch is an
// unexpected_message failure.
func (h *Cache) FullPullMapOneOfItems(
	startSeq int,
	cipherSuite dtlsconfig.CipherSuite,
	rules ...HandshakeCachePullRule,
) HandshakeCachePullResult {
	rule, item, ready, err := h.pullOneOf(startSeq, rules)
	if err != nil || !ready {
		return HandshakeCachePullResult{
			NextSequence: startSeq,
			Ready:        ready,
			Err:          err,
		}
	}

	return h.fullPullMapCacheItems(
		startSeq,
		cipherSuite,
		[]HandshakeCachePullRule{rule},
		[]*HandshakeCacheItem{item},
	)
}

func (h *Cache) pullOneOf( //nolint:cyclop
	startSeq int,
	rules []HandshakeCachePullRule,
) (HandshakeCachePullRule, *HandshakeCacheItem, bool, error) {
	if startSeq < 0 || startSeq > int(^uint16(0)) {
		return HandshakeCachePullRule{}, nil, true, fmt.Errorf(
			"%w: %w",
			dtlserrors.ErrHandshakeSequenceOverflow,
			&alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
		)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	var selectedRule HandshakeCachePullRule
	var selectedItem *HandshakeCacheItem
	conflict := false
	for _, item := range h.cache {
		if item.MessageSequence != uint16(startSeq) { //nolint:gosec // startSeq is bounded above.
			continue
		}

		matchedMetadata := false
		matchedRule := -1
		for i, rule := range rules {
			if item.IsClient != rule.IsClient || item.Epoch != rule.Epoch {
				continue
			}
			matchedMetadata = true
			if item.Typ == rule.Typ {
				matchedRule = i

				break
			}
		}
		if !matchedMetadata {
			continue
		}
		if matchedRule < 0 {
			conflict = true

			continue
		}
		if selectedItem != nil && selectedItem.Typ != item.Typ {
			conflict = true

			continue
		}

		selectedRule = rules[matchedRule]
		selectedItem = item
	}

	if conflict {
		return HandshakeCachePullRule{}, nil, true, fmt.Errorf(
			"%w: %w",
			dtlserrors.ErrUnexpectedHandshakeMessage,
			&alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage},
		)
	}
	if selectedItem == nil {
		return HandshakeCachePullRule{}, nil, false, nil
	}

	return selectedRule, selectedItem, true, nil
}

// PullSequential selects messages at consecutive sequence numbers. Missing
// messages are incomplete.
func (h *Cache) PullSequential( //nolint:cyclop,gocognit // Ordered required/optional conflict handling.
	startSeq int,
	rules ...HandshakeCachePullRule,
) HandshakeCacheItemPullResult {
	h.mu.Lock()
	defer h.mu.Unlock()

	items := make([]*HandshakeCacheItem, len(rules))
	seq := startSeq
	selected := 0
	for i, rule := range rules {
		if seq < 0 || seq > int(^uint16(0)) {
			return HandshakeCacheItemPullResult{
				NextSequence: startSeq,
				Ready:        true,
				Err: fmt.Errorf(
					"%w: %w",
					dtlserrors.ErrHandshakeSequenceOverflow,
					&alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
				),
			}
		}

		conflicts := make([]*HandshakeCacheItem, 0, 1)
		for _, item := range h.cache {
			if item.IsClient != rule.IsClient || item.Epoch != rule.Epoch ||
				item.MessageSequence != uint16(seq) { //nolint:gosec // seq is bounded above.
				continue
			}
			if item.Typ == rule.Typ {
				items[i] = item
			} else {
				conflicts = append(conflicts, item)
			}
		}

		if items[i] == nil {
			if rule.Optional {
				for _, conflict := range conflicts {
					if !matchesAnyHandshakePullRule(conflict, rules[i+1:]) {
						return unexpectedHandshakePull(startSeq)
					}
				}

				continue
			}
			if len(conflicts) != 0 {
				return unexpectedHandshakePull(startSeq)
			}

			return HandshakeCacheItemPullResult{NextSequence: startSeq}
		}
		if len(conflicts) != 0 {
			return unexpectedHandshakePull(startSeq)
		}

		selected++
		seq++
	}
	if selected == 0 {
		return HandshakeCacheItemPullResult{NextSequence: startSeq}
	}

	return HandshakeCacheItemPullResult{
		NextSequence: seq,
		Items:        items,
		Ready:        true,
	}
}

func matchesAnyHandshakePullRule(item *HandshakeCacheItem, rules []HandshakeCachePullRule) bool {
	for _, rule := range rules {
		if item.Typ == rule.Typ && item.IsClient == rule.IsClient && item.Epoch == rule.Epoch {
			return true
		}
	}

	return false
}

func unexpectedHandshakePull(startSeq int) HandshakeCacheItemPullResult {
	return HandshakeCacheItemPullResult{
		NextSequence: startSeq,
		Ready:        true,
		Err: fmt.Errorf(
			"%w: %w",
			dtlserrors.ErrUnexpectedHandshakeMessage,
			&alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage},
		),
	}
}

func (h *Cache) fullPullMapCacheItems(
	startSeq int,
	cipherSuite dtlsconfig.CipherSuite,
	rules []HandshakeCachePullRule,
	ci []*HandshakeCacheItem,
) HandshakeCachePullResult {
	out := make(map[handshake.Type]handshake.Message)
	items := make([]DecodedHandshakeCacheItem, 0, len(rules))
	seq := startSeq
	keyExchangeAlgorithm := keyExchangeAlgorithmForCipherSuite(cipherSuite)
	for i, r := range rules {
		typ := r.Typ
		item := ci[i]
		if item == nil {
			continue
		}
		parsed, err := h.decodeGenericHandshakeItem(
			item, r.Typ, uint16(seq), keyExchangeAlgorithm, //nolint:gosec // selection bounded seq above.
		)
		if err != nil {
			return HandshakeCachePullResult{
				NextSequence: startSeq,
				Ready:        true,
				Err: fmt.Errorf(
					"%w: %w",
					err,
					&alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
				),
			}
		}
		seq++
		out[typ] = parsed.Message
		items = append(items, DecodedHandshakeCacheItem{Raw: item, Parsed: parsed})
	}
	if len(items) == 0 {
		return HandshakeCachePullResult{NextSequence: seq}
	}

	return HandshakeCachePullResult{
		NextSequence: seq,
		Messages:     out,
		Items:        items,
		Ready:        true,
	}
}

func keyExchangeAlgorithmForCipherSuite(cipherSuite dtlsconfig.CipherSuite) ciphersuite.KeyExchangeAlgorithm {
	if cipherSuite == nil {
		return 0
	}

	return cipherSuite.KeyExchangeAlgorithm()
}

func (h *Cache) decodeGenericHandshakeItem(
	item *HandshakeCacheItem,
	expectedType handshake.Type,
	expectedSequence uint16,
	keyExchangeAlgorithm ciphersuite.KeyExchangeAlgorithm,
) (*handshake.Handshake, error) {
	contextKeyExchangeAlgorithm := keyExchangeAlgorithm
	if expectedType != handshake.TypeServerKeyExchange && expectedType != handshake.TypeClientKeyExchange {
		contextKeyExchangeAlgorithm = 0
	}
	context := handshakeCacheDecodeContext{
		kind:                 handshakeCacheDecodeGeneric,
		keyExchangeAlgorithm: contextKeyExchangeAlgorithm,
	}

	return h.decodeHandshakeItem(
		item,
		expectedType,
		expectedSequence,
		context,
		func(data []byte) (*handshake.Handshake, error) {
			parsed := &handshake.Handshake{KeyExchangeAlgorithm: keyExchangeAlgorithm}
			if err := parsed.Unmarshal(data); err != nil {
				return nil, err
			}

			return parsed, nil
		},
	)
}

// DecodeProtectedHandshakeItem decodes and retains one DTLS 1.3 protected
// handshake message, or returns the retained value by an earlier pull.
func (h *Cache) DecodeProtectedHandshakeItem(
	item *HandshakeCacheItem,
	expectedType handshake.Type,
	expectedSequence uint16,
	decoder HandshakeCacheDecoder,
) (*handshake.Handshake, error) {
	parsed, err := h.decodeHandshakeItem(
		item,
		expectedType,
		expectedSequence,
		handshakeCacheDecodeContext{kind: handshakeCacheDecodeProtected13},
		decoder,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %w",
			err,
			&alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
		)
	}

	return parsed, nil
}

func (h *Cache) decodeHandshakeItem(
	item *HandshakeCacheItem,
	expectedType handshake.Type,
	expectedSequence uint16,
	context handshakeCacheDecodeContext,
	decoder HandshakeCacheDecoder,
) (*handshake.Handshake, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if item == nil || decoder == nil || item.Typ != expectedType || item.MessageSequence != expectedSequence {
		return nil, dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}
	if item.hasDecoded {
		if item.decodeContext != context {
			return nil, dtlserrors.ErrInvalidHandshakeTranscriptMessage
		}
		if err := validateDecodedHandshake(item, item.parsed); err != nil {
			return nil, err
		}

		return item.parsed, nil
	}

	parsed, err := decoder(item.Data)
	if err != nil {
		return nil, err
	}
	if err := validateDecodedHandshake(item, parsed); err != nil {
		return nil, err
	}

	item.parsed = parsed
	item.decodeContext = context
	item.hasDecoded = true

	return parsed, nil
}

// Validate checks that the raw and parsed views identify the same complete
// handshake message.
func (i DecodedHandshakeCacheItem) Validate() error {
	if err := validateDecodedHandshake(i.Raw, i.Parsed); err != nil {
		return err
	}
	if i.Raw.hasDecoded && i.Raw.parsed != i.Parsed {
		return dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	return nil
}

func validateDecodedHandshake( //nolint:cyclop
	item *HandshakeCacheItem,
	parsed *handshake.Handshake,
) error {
	if item == nil || parsed == nil || parsed.Message == nil {
		return dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	var rawHeader handshake.Header
	if err := rawHeader.Unmarshal(item.Data); err != nil {
		return err
	}
	if rawHeader != parsed.Header ||
		rawHeader.Type != item.Typ ||
		rawHeader.MessageSequence != item.MessageSequence ||
		rawHeader.FragmentOffset != 0 ||
		rawHeader.FragmentLength != rawHeader.Length ||
		len(item.Data) != handshake.HeaderLength+int(rawHeader.Length) ||
		parsed.Message.Type() != rawHeader.Type {
		return dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	return nil
}

// PullAndMerge calls pull and then merges the results, ignoring any null entries.
func (h *Cache) PullAndMerge(rules ...HandshakeCachePullRule) []byte {
	merged := []byte{}

	for _, p := range h.Pull(rules...) {
		if p != nil {
			merged = append(merged, p.Data...)
		}
	}

	return merged
}

// SessionHash returns the session hash for Extended Master Secret support
// https://tools.ietf.org/html/draft-ietf-tls-session-hash-06#section-4
func (h *Cache) SessionHash(hf prf.HashFunc, epoch uint16, additional ...[]byte) ([]byte, error) {
	merged := []byte{}

	// Order defined by https://tools.ietf.org/html/rfc5246#section-7.3
	handshakeBuffer := h.Pull(
		HandshakeCachePullRule{handshake.TypeClientHello, epoch, true, false},
		HandshakeCachePullRule{handshake.TypeServerHello, epoch, false, false},
		HandshakeCachePullRule{handshake.TypeCertificate, epoch, false, false},
		HandshakeCachePullRule{handshake.TypeServerKeyExchange, epoch, false, false},
		HandshakeCachePullRule{handshake.TypeCertificateRequest, epoch, false, false},
		HandshakeCachePullRule{handshake.TypeServerHelloDone, epoch, false, false},
		HandshakeCachePullRule{handshake.TypeCertificate, epoch, true, false},
		HandshakeCachePullRule{handshake.TypeClientKeyExchange, epoch, true, false},
	)

	for _, p := range handshakeBuffer {
		if p == nil {
			continue
		}

		merged = append(merged, p.Data...)
	}
	for _, a := range additional {
		merged = append(merged, a...)
	}

	hash := hf()
	if _, err := hash.Write(merged); err != nil {
		return []byte{}, err
	}

	return hash.Sum(nil), nil
}
