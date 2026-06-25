// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package flight contains shared internal flight state and helpers.
package flight

import (
	"sync"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
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

// FullPullMap pulls all handshakes between rules[0] to rules[len(rules)-1] as map.
func (h *Cache) FullPullMap(
	startSeq int,
	cipherSuite dtlsconfig.CipherSuite,
	rules ...HandshakeCachePullRule,
) (int, map[handshake.Type]handshake.Message, bool) {
	seq, msgs, _, ok := h.FullPullMapItems(startSeq, cipherSuite, rules...)

	return seq, msgs, ok
}

func (h *Cache) FullPullMapItems(
	startSeq int,
	cipherSuite dtlsconfig.CipherSuite,
	rules ...HandshakeCachePullRule,
) (int, map[handshake.Type]handshake.Message, []*HandshakeCacheItem, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	ci, ok := h.pullLastCacheItems(rules)
	if !ok {
		return startSeq, nil, nil, false
	}

	return fullPullMapCacheItems(startSeq, cipherSuite, rules, ci)
}

func (h *Cache) pullLastCacheItems(rules []HandshakeCachePullRule) ([]*HandshakeCacheItem, bool) {
	items := make([]*HandshakeCacheItem, len(rules))
	for i, rule := range rules {
		items[i] = h.lastCacheItemForRule(rule)
		if !rule.Optional && items[i] == nil {
			return nil, false
		}
	}

	return items, true
}

func (h *Cache) lastCacheItemForRule(rule HandshakeCachePullRule) *HandshakeCacheItem {
	var last *HandshakeCacheItem
	for _, c := range h.cache {
		if !cacheItemMatchesRule(c, rule) {
			continue
		}
		if last == nil || last.MessageSequence < c.MessageSequence {
			last = c
		}
	}

	return last
}

func cacheItemMatchesRule(item *HandshakeCacheItem, rule HandshakeCachePullRule) bool {
	return item.Typ == rule.Typ && item.IsClient == rule.IsClient && item.Epoch == rule.Epoch
}

func fullPullMapCacheItems(
	startSeq int,
	cipherSuite dtlsconfig.CipherSuite,
	rules []HandshakeCachePullRule,
	ci []*HandshakeCacheItem,
) (int, map[handshake.Type]handshake.Message, []*HandshakeCacheItem, bool) {
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
		rawHandshake, ok := unmarshalCachedHandshake(item, keyExchangeAlgorithm)
		if !ok {
			return startSeq, nil, nil, false
		}
		if uint16(seq) != rawHandshake.Header.MessageSequence { //nolint:gosec // G115
			// There is a gap. Some messages are not arrived.
			return startSeq, nil, nil, false
		}
		seq++
		out[typ] = rawHandshake.Message
		items = append(items, item)
	}
	if len(items) == 0 {
		return seq, nil, nil, false
	}

	return seq, out, items, true
}

func keyExchangeAlgorithmForCipherSuite(cipherSuite dtlsconfig.CipherSuite) ciphersuite.KeyExchangeAlgorithm {
	if cipherSuite == nil {
		return 0
	}

	return cipherSuite.KeyExchangeAlgorithm()
}

func unmarshalCachedHandshake(
	item *HandshakeCacheItem,
	keyExchangeAlgorithm ciphersuite.KeyExchangeAlgorithm,
) (*handshake.Handshake, bool) {
	rawHandshake := &handshake.Handshake{
		KeyExchangeAlgorithm: keyExchangeAlgorithm,
	}
	if err := rawHandshake.Unmarshal(item.Data); err != nil {
		return nil, false
	}

	return rawHandshake, true
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
