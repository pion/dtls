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
	body            []byte
	extensionOffset int
	extensions      []extension.Raw
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

// Offered reports whether the ClientHello contained typ.
func (s ClientHelloSnapshot) Offered(typ extension.Type) bool {
	return slices.ContainsFunc(s.extensions, func(raw extension.Raw) bool { return raw.Type == typ })
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

// Record retains snapshot as the current offer, rejecting a changed CID on retry.
func (s *ClientHelloSnapshots) Record(snapshot ClientHelloSnapshot) error {
	if !snapshot.Valid() {
		return nil
	}
	if s.initial.Valid() {
		first, firstPresent := s.initial.Extension(extension.TypeConnectionID)
		second, secondPresent := snapshot.Extension(extension.TypeConnectionID)
		if firstPresent != secondPresent || !bytes.Equal(first.Data, second.Data) {
			return negotiationError(dtlserrors.ErrInvalidClientHello,
				fmt.Errorf("connection_id changed after retry: %w", dtlserrors.ErrInvalidClientHello),
				alert.IllegalParameter)
		}
	} else {
		s.initial = snapshot
	}
	s.current = snapshot

	return nil
}

// RecordWire retains the exact ClientHello body from an unfragmented DTLS
// handshake.
func (s *ClientHelloSnapshots) RecordWire(rawHandshake []byte) error {
	var header handshake.Header
	if err := header.Unmarshal(rawHandshake); err != nil {
		return negotiationError(dtlserrors.ErrInvalidClientHello, fmt.Errorf("header: %w", err), alert.DecodeError)
	}
	if header.Type != handshake.TypeClientHello ||
		header.FragmentOffset != 0 || header.FragmentLength != header.Length ||
		int(header.Length) != len(rawHandshake)-handshake.HeaderLength {
		return negotiationError(dtlserrors.ErrInvalidClientHello,
			fmt.Errorf("invalid wire handshake: %w", dtlserrors.ErrInvalidClientHello), alert.DecodeError)
	}

	snapshot, err := snapshotClientHello(rawHandshake[handshake.HeaderLength:])
	if err != nil {
		return negotiationError(dtlserrors.ErrInvalidClientHello,
			fmt.Errorf("wire handshake: %w", err), alert.DecodeError)
	}

	return s.Record(snapshot)
}

// FinalizeClientHello clones and validates a ClientHello before and after the
// hook.
func FinalizeClientHello(
	base *handshake.MessageClientHello,
	hook func(handshake.MessageClientHello) handshake.Message,
) (*handshake.MessageClientHello, ClientHelloSnapshot, error) {
	clientHello, err := validatedClientHello(base)
	if err == nil && hook != nil {
		clientHello, err = validatedClientHello(hook(*clientHello))
	}
	if err != nil {
		return nil, ClientHelloSnapshot{}, err
	}

	body, err := clientHello.Marshal()
	if err == nil {
		var snapshot ClientHelloSnapshot
		if snapshot, err = snapshotClientHello(body); err == nil {
			return clientHello, snapshot, nil
		}
	}

	return nil, ClientHelloSnapshot{}, negotiationError(dtlserrors.ErrInvalidClientHello, err, alert.InternalError)
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

	return ClientHelloSnapshot{
		body: bytes.Clone(body), extensionOffset: len(body) - len(extensionData), extensions: extensions,
	}, nil
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

	err := ValidateResponseExtensions(offer, serverHello.Extensions, func(typ extension.Type) bool {
		return (isHelloRetryRequest && typ == extension.TypeCookie) ||
			(!isHelloRetryRequest && typ == extension.TypeRenegotiationInfo &&
				clientHelloHasCipherSuite(offer, 0x00ff))
	})
	if err != nil {
		return fmt.Errorf("%w: %w", dtlserrors.ErrInvalidServerHello, err)
	}

	return nil
}

// ValidateServerHello12Context rejects responses that the wire codec
// classified as HelloRetryRequest or DTLS 1.3 ServerHello.
func ValidateServerHello12Context(serverHello *handshake.MessageServerHello) error {
	random := serverHello.Random.MarshalFixed()
	is13 := slices.ContainsFunc(serverHello.Extensions, func(value extension.Value) bool {
		typ := value.ExtensionType()

		return typ == extension.TypeSupportedVersions || typ == extension.TypeKeyShare || typ == extension.TypePreSharedKey
	})
	if !bytes.Equal(random[:], handshake.HelloRetryRequestRandom()) && !is13 {
		return nil
	}

	return negotiationError(dtlserrors.ErrInvalidServerHello,
		fmt.Errorf("response is not a DTLS 1.2 ServerHello: %w", dtlserrors.ErrExtensionNotAllowed), alert.IllegalParameter)
}

func ValidateResponseExtensions(
	offer ClientHelloSnapshot,
	values []extension.Value,
	allowed func(extension.Type) bool,
) error {
	for _, value := range values {
		typ := value.ExtensionType()
		if !offer.Offered(typ) && (allowed == nil || !allowed(typ)) {
			return fmt.Errorf("extension %d: %w: %w", typ, dtlserrors.ErrUnsolicitedExtension,
				&alert.Alert{Level: alert.Fatal, Description: alert.UnsupportedExtension})
		}
	}

	return nil
}

// FinalizeServerHello clones and validates a ServerHello before and after its
// hook.
func FinalizeServerHello(
	base *handshake.MessageServerHello,
	hook func(handshake.MessageServerHello) handshake.Message,
	offer ClientHelloSnapshot,
) (*handshake.MessageServerHello, error) {
	serverHello, err := validatedServerHello(base)
	if err == nil && hook != nil {
		serverHello, err = validatedServerHello(hook(*serverHello))
	}
	if err != nil {
		return nil, err
	}
	if ValidateServerHello12Context(serverHello) != nil {
		return nil, invalidHook(dtlserrors.ErrInvalidServerHello, serverHello, dtlserrors.ErrInvalidServerHello)
	}
	if err := ValidateServerHelloResponse(offer, serverHello); err != nil {
		return nil, err
	}

	return serverHello, nil
}

// ConnectionIDOffer returns the offered connection ID and its presence.
func ConnectionIDOffer(snapshot ClientHelloSnapshot) ([]byte, bool) {
	raw, ok := snapshot.Extension(extension.TypeConnectionID)
	if !ok || len(raw.Data) == 0 || len(raw.Data) != int(raw.Data[0])+1 {
		return nil, false
	}

	return raw.Data[1:], true
}

// ConnectionID is the session-wide CID negotiation decision.
type ConnectionID struct {
	ClientCID, ServerCID []byte
}

// DecideConnectionID derives a CID decision from an offer and final response.
func DecideConnectionID(offer ClientHelloSnapshot, responses []extension.Value) *ConnectionID {
	clientCID, offered := ConnectionIDOffer(offer)
	if offered {
		for _, value := range responses {
			if response, ok := value.(*extension.ConnectionID); ok && response != nil {
				return &ConnectionID{ClientCID: clientCID, ServerCID: bytes.Clone(response.CID)}
			}
		}
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
		return nil, invalidHook(dtlserrors.ErrInvalidClientHello, message, nil)
	}
	if slices.Contains(clientHello.CompressionMethods, nil) {
		err := fmt.Errorf("hook returned a nil ClientHello value: %w", dtlserrors.ErrInvalidCompressionMethod)

		return nil, invalidHook(dtlserrors.ErrInvalidClientHello, message, err)
	}

	canonical := &handshake.MessageClientHello{}
	if err := canonicalize(clientHello, canonical, dtlserrors.ErrInvalidClientHello); err != nil {
		return nil, err
	}

	return canonical, nil
}

func validatedServerHello(message handshake.Message) (*handshake.MessageServerHello, error) {
	serverHello, ok := message.(*handshake.MessageServerHello)
	if !ok || serverHello == nil {
		return nil, invalidHook(dtlserrors.ErrInvalidServerHello, message, nil)
	}
	canonical := &handshake.MessageServerHello{}
	if err := canonicalize(serverHello, canonical, dtlserrors.ErrInvalidServerHello); err != nil {
		return nil, err
	}

	return canonical, nil
}

func canonicalize(message, canonical handshake.Message, kind error) error {
	raw, err := message.Marshal()
	if err == nil {
		err = canonical.Unmarshal(raw)
	}
	if err != nil {
		return invalidHook(kind, message, err)
	}

	return nil
}

func invalidHook(kind error, message handshake.Message, err error) error {
	if err == nil {
		err = fmt.Errorf("hook returned %T: %w", message, kind)
	}

	return negotiationError(kind, err, alert.InternalError)
}

func negotiationError(kind, err error, description alert.Description) error {
	return fmt.Errorf("%w: %w: %w", kind, err, &alert.Alert{Level: alert.Fatal, Description: description})
}
