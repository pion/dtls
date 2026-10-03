// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import dtlsstate "github.com/pion/dtls/v4/internal/state"

// SessionTicket contains the metadata needed to use a DTLS 1.3 ticket.
type SessionTicket = dtlsstate.SessionTicket

// Session store data needed in resumption.
type Session struct {
	// ID stores a DTLS 1.2 session ID or a DTLS 1.3 ticket identity.
	ID []byte
	// Secret stores a DTLS 1.2 master secret or a DTLS 1.3 resumption PSK.
	Secret []byte //nolint:gosec // no real risk of exporting the secret.
	// Ticket is non-nil for DTLS 1.3 sessions.
	Ticket *SessionTicket
}

// SessionStore defines methods needed for session resumption.
type SessionStore interface {
	// Set save a session.
	// For client, use server name as key.
	// For server, use session id.
	Set(key []byte, s Session) error
	// Get fetch a session.
	Get(key []byte) (Session, error)
	// Del clean saved session.
	Del(key []byte) error
}
