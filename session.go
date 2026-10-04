// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"crypto"
	"time"

	"github.com/pion/dtls/v4/internal/ciphersuite"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/internal/util"
	"github.com/pion/dtls/v4/pkg/protocol"
)

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

// ticketPSK ignores expired tickets and sessions from other protocol versions or names.
func (s Session) ticketPSK(serverName string, now time.Time) *dtlsstate.PSK {
	ticket := s.Ticket
	if ticket == nil || ticket.ServerName != serverName || len(s.ID) == 0 {
		return nil
	}
	age := now.Sub(ticket.CreatedAt)
	if !validSessionTicketAge(age, ticket.Lifetime) {
		return nil
	}
	suite := ciphersuite.ForID(ticket.CipherSuite)
	if suite == nil || !suite.Capabilities().SupportsVersion(protocol.Version1_3) || len(s.Secret) != suite.HashFunc()().Size() {
		return nil
	}
	hashID := crypto.SHA256
	if suite.HashFunc()().Size() == crypto.SHA384.Size() {
		hashID = crypto.SHA384
	}

	return &dtlsstate.PSK{
		Identity: bytes.Clone(s.ID), Secret: bytes.Clone(s.Secret), Hash: hashID,
		//nolint:gosec // Age is bounded to seven days, addition wraps modulo 2^32 https://datatracker.ietf.org/doc/html/rfc9846#section-4.3.11.1
		ObfuscatedTicketAge: uint32(age.Milliseconds()) + ticket.AgeAdd,
		PeerCertificates:    util.CloneByteSlices(ticket.PeerCertificates),
	}
}

func validSessionTicketAge(age time.Duration, lifetime uint32) bool {
	const maxLifetime = 7 * 24 * 60 * 60

	return age >= 0 && lifetime > 0 && lifetime <= maxLifetime && age < time.Duration(lifetime)*time.Second
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

// EarlyDataSessionStore optionally supports replay-protected early data.
// Claim atomically marks a ticket used for early data, returning true only once.
// Claims must be shared across all servers using the tickets and retained until
// expiresAt, even if the session is updated or deleted. Claim preserves the
// session for ordinary resumption. Errors reject early data, not resumption.
type EarlyDataSessionStore interface {
	SessionStore
	Claim(ticket []byte, expiresAt time.Time) (bool, error)
}
