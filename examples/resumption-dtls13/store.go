// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v4"
	"golang.org/x/crypto/scrypt"
)

var errTicketFile = errors.New("invalid ticket file or incorrect passphrase")

type sessionStore struct {
	sync.Mutex
	sessions map[string]dtls.Session
	claims   map[string]time.Time
}

func newStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]dtls.Session), claims: make(map[string]time.Time)}
}

func (s *sessionStore) Set(key []byte, session dtls.Session) error {
	s.Lock()
	defer s.Unlock()
	s.sessions[string(key)] = session

	return nil
}

func (s *sessionStore) Get(key []byte) (dtls.Session, error) {
	s.Lock()
	defer s.Unlock()
	session := s.sessions[string(key)]
	if session.Ticket != nil && time.Since(session.Ticket.CreatedAt) >= time.Duration(session.Ticket.Lifetime)*time.Second {
		delete(s.sessions, string(key))

		return dtls.Session{}, nil
	}

	return session, nil
}

func (s *sessionStore) Del(key []byte) error {
	s.Lock()
	defer s.Unlock()
	delete(s.sessions, string(key))

	return nil
}

func (s *sessionStore) Claim(ticket []byte, expiresAt time.Time) (bool, error) {
	s.Lock()
	defer s.Unlock()
	now := time.Now()
	for key, expiry := range s.claims {
		if !now.Before(expiry) {
			delete(s.claims, key)
		}
	}
	if _, used := s.claims[string(ticket)]; used || !now.Before(expiresAt) {
		return false, nil
	}
	s.claims[string(ticket)] = expiresAt

	return true, nil
}

// random 16-byte salt, GCM nonce, authenticated encrypted JSON.
func ticketCipher(password string, salt []byte) (cipher.AEAD, error) {
	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func (s *sessionStore) load(path, password string) (bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(data) < 16+12+16 {
		return false, errTicketFile
	}
	aead, err := ticketCipher(password, data[:16])
	if err != nil {
		return false, err
	}
	plaintext, err := aead.Open(nil, data[16:28], data[28:], nil)
	if err != nil {
		return false, errTicketFile
	}
	defer clear(plaintext)
	if err = json.Unmarshal(plaintext, &s.sessions); err != nil {
		return false, err
	}
	if s.sessions == nil {
		s.sessions = make(map[string]dtls.Session)
	}
	for key := range s.sessions {
		// drops expired tickets before offering 0-RTT.
		_, _ = s.Get([]byte(key))
	}

	return len(s.sessions) > 0, nil
}

func (s *sessionStore) save(path, password string) error {
	s.Lock()
	plaintext, err := json.Marshal(s.sessions)
	s.Unlock()
	if err != nil {
		return err
	}
	defer clear(plaintext)
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return err
	}
	aead, err := ticketCipher(password, salt)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	data := aead.Seal(nil, nonce, plaintext, nil)
	data = append(append(salt, nonce...), data...) //nolint:makezero
	file, err := os.CreateTemp(filepath.Dir(path), ".dtls-ticket-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name()) //nolint:errcheck
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if err = errors.Join(writeErr, closeErr); err != nil {
		return err
	}

	return os.Rename(file.Name(), path) //nolint:gosec
}

type connectionStore struct {
	*sessionStore
	accepted atomic.Bool
}

func (s *connectionStore) Claim(ticket []byte, expiresAt time.Time) (bool, error) {
	accepted, err := s.sessionStore.Claim(ticket, expiresAt)
	s.accepted.Store(accepted)

	return accepted, err
}
