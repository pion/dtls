// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package extensionnegotiation finalizes and retains ClientHello offers.
package extensionnegotiation

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// ClientHelloSnapshot is an immutable copy of a validated ClientHello body.
type ClientHelloSnapshot struct {
	body       []byte
	extensions []extension.Raw
}

// Valid reports whether the snapshot contains a ClientHello.
func (s ClientHelloSnapshot) Valid() bool { return len(s.body) != 0 }

// Extension returns a copy of the extension with typ.
func (s ClientHelloSnapshot) Extension(typ extension.Type) (extension.Raw, bool) {
	for _, raw := range s.extensions {
		if raw.Type == typ {
			raw.Data = bytes.Clone(raw.Data)

			return raw, true
		}
	}

	return extension.Raw{}, false
}

// ClientHelloSnapshots retains the initial and most recent offers.
// Its snapshots are immutable.
type ClientHelloSnapshots struct {
	initial ClientHelloSnapshot
	current ClientHelloSnapshot
}

// Initial returns the initial offer.
func (s ClientHelloSnapshots) Initial() ClientHelloSnapshot { return s.initial }

// Current returns the most recent offer.
func (s ClientHelloSnapshots) Current() ClientHelloSnapshot { return s.current }

// Reset removes all retained offers.
func (s *ClientHelloSnapshots) Reset() { *s = ClientHelloSnapshots{} }

// Record retains snapshot as the current offer.
func (s *ClientHelloSnapshots) Record(snapshot ClientHelloSnapshot) {
	if !snapshot.Valid() {
		return
	}
	if !s.initial.Valid() {
		s.initial = snapshot
	}
	s.current = snapshot
}

// RecordWire retains the exact ClientHello body from an unfragmented DTLS
// handshake.
func (s *ClientHelloSnapshots) RecordWire(rawHandshake []byte) error {
	var header handshake.Header
	if err := header.Unmarshal(rawHandshake); err != nil {
		return fmt.Errorf(
			"%w: header: %w: %w",
			dtlserrors.ErrInvalidClientHello,
			err,
			&alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
		)
	}
	if header.Type != handshake.TypeClientHello ||
		header.FragmentOffset != 0 || header.FragmentLength != header.Length ||
		int(header.Length) != len(rawHandshake)-handshake.HeaderLength {
		return fmt.Errorf(
			"%w: invalid wire handshake: %w",
			dtlserrors.ErrInvalidClientHello,
			&alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
		)
	}

	snapshot, err := snapshotClientHello(rawHandshake[handshake.HeaderLength:])
	if err != nil {
		return fmt.Errorf(
			"%w: wire handshake: %w: %w",
			dtlserrors.ErrInvalidClientHello,
			err,
			&alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
		)
	}
	s.Record(snapshot)

	return nil
}

// FinalizeClientHello clones and validates a ClientHello before and after the
// hook.
func FinalizeClientHello(
	base *handshake.MessageClientHello,
	hook func(handshake.MessageClientHello) handshake.Message,
) (*handshake.MessageClientHello, ClientHelloSnapshot, error) {
	clientHello, err := canonicalClientHello(base)
	if err != nil {
		return nil, ClientHelloSnapshot{}, err
	}

	message := handshake.Message(clientHello)
	if hook != nil {
		message = hook(*clientHello)
	}
	clientHello, err = canonicalClientHello(message)
	if err != nil {
		return nil, ClientHelloSnapshot{}, err
	}

	body, err := clientHello.Marshal()
	if err != nil {
		return nil, ClientHelloSnapshot{}, fmt.Errorf(
			"%w: %w: %w",
			dtlserrors.ErrInvalidClientHello,
			err,
			&alert.Alert{Level: alert.Fatal, Description: alert.InternalError},
		)
	}
	snapshot, err := snapshotClientHello(body)
	if err != nil {
		return nil, ClientHelloSnapshot{}, fmt.Errorf(
			"%w: %w: %w",
			dtlserrors.ErrInvalidClientHello,
			err,
			&alert.Alert{Level: alert.Fatal, Description: alert.InternalError},
		)
	}

	return clientHello, snapshot, nil
}

func snapshotClientHello(body []byte) (ClientHelloSnapshot, error) {
	extensionData, err := clientHelloExtensions(body)
	if err != nil {
		return ClientHelloSnapshot{}, err
	}
	extensions, err := extension.ParseList(extensionData)
	if err != nil {
		return ClientHelloSnapshot{}, fmt.Errorf("extensions: %w", err)
	}

	return ClientHelloSnapshot{body: bytes.Clone(body), extensions: extensions}, nil
}

func clientHelloExtensions(body []byte) ([]byte, error) {
	if len(body) < 2+handshake.RandomLength {
		return nil, dtlserrors.ErrBufferTooSmall
	}

	remainder := body[2+handshake.RandomLength:]
	for _, width := range []int{1, 1, 2, 1} { // session ID, cookie, cipher suites, compression
		if len(remainder) < width {
			return nil, dtlserrors.ErrBufferTooSmall
		}
		length := int(remainder[0])
		if width == 2 {
			length = int(binary.BigEndian.Uint16(remainder))
		}
		if len(remainder)-width < length {
			return nil, dtlserrors.ErrBufferTooSmall
		}
		remainder = remainder[width+length:]
	}

	return remainder, nil
}

func canonicalClientHello(message handshake.Message) (*handshake.MessageClientHello, error) {
	clientHello, ok := message.(*handshake.MessageClientHello)
	if !ok || clientHello == nil {
		return nil, fmt.Errorf(
			"%w: hook returned %T: %w",
			dtlserrors.ErrInvalidClientHello,
			message,
			&alert.Alert{Level: alert.Fatal, Description: alert.InternalError},
		)
	}
	if slices.Contains(clientHello.CompressionMethods, nil) || containsNilExtension(clientHello.Extensions) {
		return nil, fmt.Errorf(
			"%w: hook returned a nil ClientHello value: %w",
			dtlserrors.ErrInvalidClientHello,
			&alert.Alert{Level: alert.Fatal, Description: alert.InternalError},
		)
	}

	raw, err := clientHello.Marshal()
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %w: %w",
			dtlserrors.ErrInvalidClientHello,
			err,
			&alert.Alert{Level: alert.Fatal, Description: alert.InternalError},
		)
	}
	canonical := &handshake.MessageClientHello{}
	if err := canonical.Unmarshal(raw); err != nil {
		return nil, fmt.Errorf(
			"%w: %w: %w",
			dtlserrors.ErrInvalidClientHello,
			err,
			&alert.Alert{Level: alert.Fatal, Description: alert.InternalError},
		)
	}

	return canonical, nil
}

func containsNilExtension(values []extension.Value) bool {
	for _, value := range values {
		if value == nil {
			return true
		}
		reflected := reflect.ValueOf(value)
		if reflected.Kind() == reflect.Pointer && reflected.IsNil() {
			return true
		}
	}

	return false
}
