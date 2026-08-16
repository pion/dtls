// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package extensionnegotiation finalizes and retains ClientHello offers.
package extensionnegotiation

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	clientHello, err := validatedClientHello(base)
	if err != nil {
		return nil, ClientHelloSnapshot{}, err
	}

	message := handshake.Message(clientHello)
	if hook != nil {
		message = hook(*clientHello)
	}
	clientHello, err = validatedClientHello(message)
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

// ValidateServerHelloResponse validates response types against the exact final ClientHello
// offer.
//
// DTLS 1.2:
// "An extension type MUST NOT appear in the ServerHello unless the same
// extension type appeared in the corresponding ClientHello."
//
// https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.4
//
// DTLS 1.3:
// "Implementations MUST NOT send extension responses (i.e., in the ServerHello,
// EncryptedExtensions, HelloRetryRequest, and Certificate messages)
// if the remote endpoint did not send the corresponding extension requests"
// https://www.rfc-editor.org/info/rfc9846/#section-4.3
//
// DTLS 1.2 exception:
// "sending a "renegotiation_info" extension in response to a ClientHello
// containing only the SCSV is an explicit exception"
//
// https://www.rfc-editor.org/rfc/rfc5746#section-3.6
func ValidateServerHelloResponse(
	offer ClientHelloSnapshot,
	serverHello *handshake.MessageServerHello,
) error {
	random := serverHello.Random.MarshalFixed()
	isHelloRetryRequest := bytes.Equal(random[:], handshake.HelloRetryRequestRandom())
	offeredTypes := make(map[extension.Type]struct{}, len(offer.extensions))
	for _, value := range offer.extensions {
		offeredTypes[value.Type] = struct{}{}
	}

	for _, value := range serverHello.Extensions {
		typ := value.ExtensionType()
		_, offered := offeredTypes[typ]
		if offered ||
			(isHelloRetryRequest && typ == extension.TypeCookie) ||
			(!isHelloRetryRequest && typ == extension.TypeRenegotiationInfo &&
				clientHelloHasCipherSuite(offer, 0x00ff)) {
			continue
		}

		return fmt.Errorf(
			"extension %d: %w: %w",
			typ,
			dtlserrors.ErrUnsolicitedExtension,
			&alert.Alert{Level: alert.Fatal, Description: alert.UnsupportedExtension},
		)
	}

	return nil
}

func clientHelloHasCipherSuite(offer ClientHelloSnapshot, id uint16) bool {
	var clientHello handshake.MessageClientHello

	return clientHello.Unmarshal(offer.body) == nil && slices.Contains(clientHello.CipherSuiteIDs, id)
}

func validatedClientHello(message handshake.Message) (*handshake.MessageClientHello, error) {
	clientHello, ok := message.(*handshake.MessageClientHello)
	if !ok || clientHello == nil {
		return nil, fmt.Errorf(
			"%w: hook returned %T: %w",
			dtlserrors.ErrInvalidClientHello,
			message,
			&alert.Alert{Level: alert.Fatal, Description: alert.InternalError},
		)
	}
	if slices.Contains(clientHello.CompressionMethods, nil) {
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
