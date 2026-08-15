// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package flight contains shared internal flight state and helpers.
package flight

import (
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

func NewCache() *Cache {
	return &Cache{}
}

func (h *Cache) Push(data []byte, epoch, messageSequence uint16, typ handshake.Type, isClient bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cache = append(h.cache, &HandshakeCacheItem{
		Data:            data,
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

	return fullPullMapCacheItems(startSeq, cipherSuite, rules, selection.Items)
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

	return fullPullMapCacheItems(
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

func fullPullMapCacheItems(
	startSeq int,
	cipherSuite dtlsconfig.CipherSuite,
	rules []HandshakeCachePullRule,
	ci []*HandshakeCacheItem,
) HandshakeCachePullResult {
	out := make(map[handshake.Type]handshake.Message)
	items := make([]*HandshakeCacheItem, 0, len(rules))
	seq := startSeq
	keyExchangeAlgorithm := keyExchangeAlgorithmForCipherSuite(cipherSuite)
	for i, r := range rules {
		typ := r.Typ
		item := ci[i]
		if item == nil {
			continue
		}
		parsed := &handshake.Handshake{KeyExchangeAlgorithm: keyExchangeAlgorithm}
		err := parsed.Unmarshal(item.Data)
		if err == nil {
			err = validateCachedHandshake(
				item,
				parsed,
				r.Typ,
				uint16(seq), //nolint:gosec // selection bounded seq above.
			)
		}
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
		items = append(items, item)
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

func validateCachedHandshake( //nolint:cyclop // Each condition validates a distinct wire/cache invariant.
	item *HandshakeCacheItem,
	parsed *handshake.Handshake,
	expectedType handshake.Type,
	expectedSequence uint16,
) error {
	if item == nil || parsed == nil || parsed.Message == nil {
		return dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	var rawHeader handshake.Header
	if err := rawHeader.Unmarshal(item.Data); err != nil {
		return err
	}
	if rawHeader != parsed.Header ||
		rawHeader.Type != expectedType ||
		rawHeader.Type != item.Typ ||
		rawHeader.MessageSequence != expectedSequence ||
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
