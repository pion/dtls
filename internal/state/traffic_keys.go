// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"bytes"
	"sync"

	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
)

// TrafficGeneration binds an epoch and traffic-secret generation to the
// record protection derived from that secret.
// Caller must not modify the secret or protection after creation.
type TrafficGeneration struct {
	Epoch      uint16
	Generation uint64
	Secret     []byte // nolint:gosec
	Protection cryptosuite.TrafficProtection
}

func (g *TrafficGeneration) Clone() *TrafficGeneration {
	if g == nil {
		return nil
	}

	return &TrafficGeneration{Epoch: g.Epoch, Generation: g.Generation, Secret: bytes.Clone(g.Secret), Protection: g.Protection}
}

// TrafficKeyState owns directional DTLS 1.3 traffic generations.
type TrafficKeyState struct {
	mu sync.RWMutex

	writeCurrent *TrafficGeneration
	writeOld     map[uint16]*TrafficGeneration
	readCurrent  *TrafficGeneration
	readOld      map[uint16]*TrafficGeneration
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
func (s *TrafficKeyState) Write(epoch uint16) (*TrafficGeneration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.writeCurrent != nil && s.writeCurrent.Epoch == epoch {
		return s.writeCurrent, true
	}
	generation, ok := s.writeOld[epoch]

	return generation, ok
}

// Read returns the read generation associated with epoch.
func (s *TrafficKeyState) Read(epoch uint16) (*TrafficGeneration, bool) {
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

// ReadCandidates appends installed generations matching the low epoch bits to
// candidates. The current generation is added first if it matches.
func (s *TrafficKeyState) ReadCandidates(
	epochLow uint8,
	candidates []*TrafficGeneration,
) []*TrafficGeneration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	const epochLowMask = uint16(0x3)
	if s.readCurrent != nil && uint8(s.readCurrent.Epoch&epochLowMask) == epochLow {
		candidates = append(candidates, s.readCurrent)
	}

	for _, generation := range s.readOld {
		if uint8(generation.Epoch&epochLowMask) == epochLow {
			candidates = append(candidates, generation)
		}
	}

	return candidates
}

func installTrafficGeneration(current **TrafficGeneration, old *map[uint16]*TrafficGeneration, generation *TrafficGeneration) {
	if generation == nil {
		return
	}
	if previous := *current; previous != nil && previous.Epoch != generation.Epoch {
		if *old == nil {
			*old = make(map[uint16]*TrafficGeneration)
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

func cloneTrafficGenerations(in map[uint16]*TrafficGeneration) map[uint16]*TrafficGeneration {
	if in == nil {
		return nil
	}
	out := make(map[uint16]*TrafficGeneration, len(in))
	for epoch, generation := range in {
		out[epoch] = generation.Clone()
	}

	return out
}
