// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"bytes"
	"errors"
	"math"
	"sync"
	"sync/atomic"

	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
)

// TrafficGeneration binds an epoch and traffic-secret generation to the
// record protection derived from that secret.
// Caller must not modify the secret or protection after creation.
type TrafficGeneration struct {
	Epoch      uint64
	Generation uint64
	Secret     []byte // nolint:gosec
	Protection cryptosuite.TrafficProtection
	usage      atomic.Pointer[trafficUsage]
}

type trafficUsage struct {
	sealed atomic.Uint64
	failed atomic.Uint64
}

func (g *TrafficGeneration) usageCounters() *trafficUsage {
	if usage := g.usage.Load(); usage != nil {
		return usage
	}
	g.usage.CompareAndSwap(nil, &trafficUsage{})

	return g.usage.Load()
}

// Seal counts successful encryptions, including those followed by masking or
// transport failures. Recommended usage limits are advisory.
func (g *TrafficGeneration) Seal(record cryptosuite.Record, plaintext []byte) ([]byte, error) {
	return g.usageCounters().seal(g.Protection, record, plaintext)
}

func (usage *trafficUsage) seal(protection cryptosuite.Protection, record cryptosuite.Record, plaintext []byte) ([]byte, error) {
	protected, err := protection.Seal(record, plaintext)
	if err != nil {
		return nil, err
	}
	incrementUsage(&usage.sealed)

	return protected, nil
}

// Open counts only typed authentication failures, preserving the provider error.
func (g *TrafficGeneration) Open(record cryptosuite.Record, protected []byte) ([]byte, error) {
	return g.usageCounters().open(g.Protection, record, protected)
}

func (usage *trafficUsage) open(protection cryptosuite.Protection, record cryptosuite.Record, protected []byte) ([]byte, error) {
	plaintext, err := protection.Open(record, protected)
	if errors.Is(err, cryptosuite.ErrAuthenticationFailed) {
		incrementUsage(&usage.failed)
	}
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Usage returns counters for this key. Counts saturate at math.MaxUint64.
func (g *TrafficGeneration) Usage() (sealed, failed uint64) {
	return g.usageCounters().counts()
}

func (usage *trafficUsage) counts() (sealed, failed uint64) {
	return usage.sealed.Load(), usage.failed.Load()
}

func incrementUsage(counter *atomic.Uint64) {
	for value := counter.Load(); value < math.MaxUint64; value = counter.Load() {
		if counter.CompareAndSwap(value, value+1) {
			return
		}
	}
}

func (g *TrafficGeneration) Clone() *TrafficGeneration {
	if g == nil {
		return nil
	}

	clone := &TrafficGeneration{Epoch: g.Epoch, Generation: g.Generation, Secret: bytes.Clone(g.Secret), Protection: g.Protection}
	clone.usage.Store(g.usageCounters())

	return clone
}

// TrafficKeyState owns directional DTLS 1.3 traffic generations.
type TrafficKeyState struct {
	mu sync.RWMutex

	writeCurrent *TrafficGeneration
	writeOld     map[uint64]*TrafficGeneration
	readCurrent  *TrafficGeneration
	readOld      map[uint64]*TrafficGeneration
}

// Install any supplied current write and read generations.
// Pass nil for a direction that should remain unchanged.
func (s *TrafficKeyState) Install(write, read *TrafficGeneration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	installTrafficGeneration(&s.writeCurrent, &s.writeOld, write)
	installTrafficGeneration(&s.readCurrent, &s.readOld, read)
}

// Write returns the write generation associated with epoch.
func (s *TrafficKeyState) Write(epoch uint64) (*TrafficGeneration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.writeCurrent != nil && s.writeCurrent.Epoch == epoch {
		return s.writeCurrent, true
	}
	generation, ok := s.writeOld[epoch]

	return generation, ok
}

// Read returns the read generation associated with epoch.
func (s *TrafficKeyState) Read(epoch uint64) (*TrafficGeneration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.readCurrent != nil && s.readCurrent.Epoch == epoch {
		return s.readCurrent, true
	}
	generation, ok := s.readOld[epoch]

	return generation, ok
}

// CurrentWrite returns the current write generation.
func (s *TrafficKeyState) CurrentWrite() (*TrafficGeneration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.writeCurrent, s.writeCurrent != nil
}

// CurrentRead returns the current read generation.
func (s *TrafficKeyState) CurrentRead() (*TrafficGeneration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.readCurrent, s.readCurrent != nil
}

// ReadCandidate selects the current or most recent past epoch with matching low bits.
// A missing generation does not allow falling back to an older matching epoch.
// https://www.rfc-editor.org/rfc/rfc9147.html#section-4.2.2
func (s *TrafficKeyState) ReadCandidate(epochLow uint8, currentEpoch uint64) (*TrafficGeneration, bool) {
	if epochLow > 3 {
		return nil, false
	}
	distance := (4 + (currentEpoch & 3) - uint64(epochLow)) & 3
	if distance > currentEpoch {
		return nil, false
	}

	return s.Read(currentEpoch - distance)
}

func installTrafficGeneration(current **TrafficGeneration, old *map[uint64]*TrafficGeneration, generation *TrafficGeneration) {
	if generation == nil {
		return
	}
	if previous := *current; previous != nil && previous.Epoch != generation.Epoch {
		if *old == nil {
			*old = make(map[uint64]*TrafficGeneration)
		}
		(*old)[previous.Epoch] = previous
	}
	*current = generation
}

func (s *TrafficKeyState) Clone() *TrafficKeyState {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	return &TrafficKeyState{writeCurrent: s.writeCurrent.Clone(), writeOld: cloneTrafficGenerations(s.writeOld), readCurrent: s.readCurrent.Clone(), readOld: cloneTrafficGenerations(s.readOld)}
}

func cloneTrafficGenerations(in map[uint64]*TrafficGeneration) map[uint64]*TrafficGeneration {
	if in == nil {
		return nil
	}
	out := make(map[uint64]*TrafficGeneration, len(in))
	for epoch, generation := range in {
		out[epoch] = generation.Clone()
	}

	return out
}
