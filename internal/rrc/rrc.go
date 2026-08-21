// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package rrc implements RFC 9853 path validation and amplification accounting.
package rrc

import (
	"crypto/rand"
	"math"
	"net"
	"sync"
	"time"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
)

const pathValidationTimeout = time.Second

type path struct {
	receivedBytes, sentBytes uint64
	cookie                   [protocol.ReturnRoutabilityCheckCookieLength]byte
	challengePending         bool
	expiresAt                time.Time
	timer                    *time.Timer
}

// Manager owns candidate path state. Its zero value is ready for use.
type Manager struct {
	mu    sync.Mutex
	paths map[string]*path
}

// WrapReplayMarker counts a record once, after authentication and replay validation.
func (m *Manager) WrapReplayMarker(
	marker func() bool,
	addr net.Addr,
	wireBytes int,
	activeAddress func() net.Addr,
	enabled bool,
) func() bool {
	if marker == nil || !enabled {
		return marker
	}

	marked := false

	return func() bool {
		// false means accepted out-of-order delivery.
		latest := marker()
		if !marked {
			marked = true
			m.recordReceived(addr, activeAddress(), wireBytes)
		}

		return latest
	}
}

// Start creates a challenge for an unvalidated address.
func (m *Manager) Start(
	enabled bool,
	addr, activeAddr net.Addr,
) ([protocol.ReturnRoutabilityCheckCookieLength]byte, bool, error) {
	var cookie [protocol.ReturnRoutabilityCheckCookieLength]byte
	if !enabled || sameAddress(addr, activeAddr) {
		return cookie, false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	path := m.pathLocked(addr)
	if path.challengePending {
		return cookie, false, nil
	}
	if _, err := rand.Read(cookie[:]); err != nil {
		return cookie, false, err
	}
	path.cookie = cookie
	path.challengePending = true
	m.touchLocked(addr, path)

	return cookie, true, nil
}

// Cancel allows a failed challenge write to be retried by the next record.
func (m *Manager) Cancel(addr net.Addr, cookie [protocol.ReturnRoutabilityCheckCookieLength]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	path := m.paths[pathKey(addr)]
	if path != nil && path.challengePending && path.cookie == cookie {
		path.challengePending = false
		m.touchLocked(addr, path)
	}
}

// HandleResponse accepts only a timely response from the challenged address.
func (m *Manager) HandleResponse(
	addr net.Addr,
	cookie [protocol.ReturnRoutabilityCheckCookieLength]byte,
) bool {
	key := pathKey(addr)
	m.mu.Lock()
	defer m.mu.Unlock()

	path := m.paths[key]
	if path == nil || !path.challengePending || path.cookie != cookie {
		return false
	}
	if !time.Now().Before(path.expiresAt) {
		if path.timer != nil {
			path.timer.Stop()
		}
		delete(m.paths, key)

		return false
	}
	for _, candidate := range m.paths {
		if candidate.timer != nil {
			candidate.timer.Stop()
		}
	}
	clear(m.paths)

	return true
}

// Reserve applies the three-times amplification limit to a candidate address.
func (m *Manager) Reserve(addr, activeAddr net.Addr, wireBytes int) error {
	if sameAddress(addr, activeAddr) {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	path := m.paths[pathKey(addr)]
	if path == nil || !time.Now().Before(path.expiresAt) {
		return dtlserrors.ErrAntiAmplificationLimit
	}

	limit := path.receivedBytes * 3
	if path.receivedBytes > math.MaxUint64/3 {
		limit = math.MaxUint64
	}
	wireBytesUint64 := uint64(wireBytes) //nolint:gosec
	if path.sentBytes >= limit || wireBytesUint64 > limit-path.sentBytes {
		return dtlserrors.ErrAntiAmplificationLimit
	}
	path.sentBytes += wireBytesUint64

	return nil
}

func (m *Manager) recordReceived(addr, activeAddr net.Addr, wireBytes int) {
	if wireBytes <= 0 || sameAddress(addr, activeAddr) {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	path := m.pathLocked(addr)
	if math.MaxUint64-path.receivedBytes < uint64(wireBytes) {
		path.receivedBytes = math.MaxUint64
	} else {
		path.receivedBytes += uint64(wireBytes)
	}
	if !path.challengePending {
		m.touchLocked(addr, path)
	}
}

func (m *Manager) pathLocked(addr net.Addr) *path {
	if m.paths == nil {
		m.paths = make(map[string]*path)
	}

	key := pathKey(addr)
	candidate := m.paths[key]
	if candidate == nil || (!candidate.expiresAt.IsZero() && !time.Now().Before(candidate.expiresAt)) {
		if candidate != nil && candidate.timer != nil {
			candidate.timer.Stop()
		}
		candidate = &path{}
		m.paths[key] = candidate
	}

	return candidate
}

func (m *Manager) touchLocked(addr net.Addr, path *path) {
	key := pathKey(addr)
	path.expiresAt = time.Now().Add(pathValidationTimeout)
	if path.timer != nil {
		path.timer.Reset(pathValidationTimeout)

		return
	}
	path.timer = time.AfterFunc(pathValidationTimeout, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.paths[key] == path && !time.Now().Before(path.expiresAt) {
			delete(m.paths, key)
		}
	})
}

func sameAddress(left, right net.Addr) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	return left.Network() == right.Network() && left.String() == right.String()
}

func pathKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	return addr.Network() + "\x00" + addr.String()
}
