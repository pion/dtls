// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ech

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"hash"
	"slices"

	"github.com/pion/dtls/v4/internal/clienthello"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"golang.org/x/crypto/cryptobyte"
)

// RejectionError reports authenticated ECH rejection. RetryConfigList may be
// used on a new connection.
type RejectionError struct{ RetryConfigList []byte }

func (*RejectionError) Error() string { return "server rejected ECH" }

// ClientContext retains the initial inner and outer bodies and HPKE state.
type ClientContext struct {
	Config                          Config
	Suite                           CipherSuite
	Sender                          Sender
	Inner, Outer                    []byte
	Accepted                        bool
	Rejected                        bool   // Selects the outer handshake.
	RetryConfigList                 []byte // Published only after verifying the server flight.
	InitialInner, HelloRetryRequest []byte
	nameLength                      int
	greasePSK                       []byte
}

// NewClientHello constructs an initial ECH offer without early data.
func NewClientHello(configList, body []byte) (*ClientContext, error) {
	c, err := PrepareClientHello(configList, body)
	if err != nil {
		return nil, err
	}
	if err := c.SealClientHello(c.Inner); err != nil {
		return nil, err
	}

	return c, nil
}

// PrepareClientHello constructs the inner hello before PSK binders are computed.
func PrepareClientHello(configList, body []byte) (*ClientContext, error) {
	configs, err := ParseConfigList(configList)
	if err != nil {
		return nil, err
	}
	config, suite, err := PickConfig(configs)
	if err != nil {
		return nil, err
	}
	prefix, exts, err := splitHello(body, false)
	if err != nil {
		return nil, err
	}
	if prefix[35+int(prefix[34])] != 0 {
		return nil, ErrInvalid
	}
	innerExts, nameLength, err := prepareInnerExtensions(exts)
	if err != nil {
		return nil, err
	}
	inner, err := appendExtensions(bytes.Clone(prefix), innerExts)
	if err != nil {
		return nil, err
	}

	return &ClientContext{Config: *config, Suite: suite, Inner: inner, nameLength: nameLength}, nil
}

// SealClientHello encrypts the finalized initial inner hello, including binders.
func (c *ClientContext) SealClientHello(inner []byte) error {
	if c.Sender != nil {
		return ErrInvalid
	}
	prefix, exts, err := splitHello(inner, false)
	if err != nil || !validInnerExtensions(exts) {
		return ErrInvalid
	}
	if i := extensionIndex(exts, extension.TypeServerName); i >= 0 {
		var name extension.ServerNameOffer
		if err = name.UnmarshalData(exts[i].Data); err != nil {
			return err
		}
		c.nameLength = len(name.ServerName)
	} else {
		c.nameLength = -1
	}
	c.greasePSK, err = greasePSK(exts)
	if err != nil {
		return err
	}
	encoded, err := EncodeInnerClientHello(inner, c.Config.MaxNameLength, c.nameLength)
	if err != nil {
		return err
	}
	enc, sender, err := NewSender(c.Config, c.Suite)
	if err != nil {
		return err
	}
	outer, err := sealOuterClientHello(prefix, exts, c.Config, c.Suite, enc, sender, encoded, c.greasePSK)
	if err != nil {
		return err
	}
	c.Sender, c.Inner, c.Outer = sender, bytes.Clone(inner), outer

	return nil
}

// AcceptRetry verifies HRR confirmation over its exact wire encoding.
// https://www.rfc-editor.org/rfc/rfc9849#section-6.1.4
func (c *ClientContext) AcceptRetry(hashFunc func() hash.Hash, body []byte) error {
	if len(c.HelloRetryRequest) != 0 {
		return ErrInvalid
	}
	zeroed := bytes.Clone(body)
	received, err := retryConfirmationField(zeroed)
	if err != nil {
		return err
	}
	signal := bytes.Clone(received)
	clear(received)
	expected, err := RetryConfirmation(hashFunc, c.Inner, zeroed)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expected, signal) != 1 {
		return ErrUnsupported
	}
	c.InitialInner = bytes.Clone(c.Inner)
	c.HelloRetryRequest = bytes.Clone(body)
	c.Accepted = true

	return nil
}

func retryConfirmationField(body []byte) ([]byte, error) {
	input := cryptobyte.String(body)
	var session, extensions cryptobyte.String
	if !input.Skip(34) || !input.ReadUint8LengthPrefixed(&session) || !input.Skip(3) ||
		!input.ReadUint16LengthPrefixed(&extensions) || !input.Empty() {
		return nil, ErrInvalid
	}

	return findRetryConfirmation(extensions)
}

func findRetryConfirmation(extensions cryptobyte.String) ([]byte, error) {
	for !extensions.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&typ) || !extensions.ReadUint16LengthPrefixed(&data) {
			return nil, ErrInvalid
		}
		if extension.Type(typ) != extension.TypeEncryptedClientHello {
			continue
		}
		if len(data) != 8 {
			return nil, ErrInvalid
		}

		return data, nil
	}

	return nil, ErrUnsupported
}

// Confirmation includes both inner ClientHellos when the server requested a retry.
func (c *ClientContext) Confirmation(hashFunc func() hash.Hash, body []byte) ([]byte, error) {
	return acceptanceConfirmation(hashFunc, c.Inner, c.InitialInner, c.HelloRetryRequest, body)
}

// RetryClientHello reuses the sender and sends an empty enc in ClientHello2.
// The caller validates the inner against the authenticated retry request first.
// https://www.rfc-editor.org/rfc/rfc9849#section-6.1.2
func (c *ClientContext) RetryClientHello(inner []byte) error {
	if !c.Accepted || len(c.HelloRetryRequest) == 0 {
		return ErrUnsupported
	}
	if !bytes.Equal(c.Inner, c.InitialInner) {
		if bytes.Equal(inner, c.Inner) {
			return nil
		}

		return ErrInvalid
	}
	prefix, exts, err := splitHello(inner, false)
	if err != nil {
		return err
	}
	encoded, err := EncodeInnerClientHello(inner, c.Config.MaxNameLength, c.nameLength)
	if err != nil {
		return err
	}
	prefix = bytes.Clone(prefix)
	copy(prefix[2:34], c.Outer[2:34])
	outer, err := sealOuterClientHello(prefix, exts, c.Config, c.Suite, nil, c.Sender, encoded, c.greasePSK)
	if err != nil {
		return err
	}
	c.Inner, c.Outer = bytes.Clone(inner), outer

	return nil
}

func prepareInnerExtensions(exts []extension.Raw) ([]extension.Raw, int, error) {
	var err error
	nameLength := -1
	innerExts := make([]extension.Raw, 0, len(exts)+1)
	for _, ext := range exts {
		switch ext.Type { //nolint:exhaustive
		case extension.TypeEncryptedClientHello, extension.TypeECHOuterExtensions,
			extension.TypePreSharedKey, extension.TypeEarlyData, extension.TypeCookie:
			return nil, 0, ErrUnsupported
		case extension.TypeRenegotiationInfo, extension.TypeSupportedPointFormats, extension.TypeExtendedMasterSecret:
			continue
		case extension.TypeSupportedVersions:
			var versions extension13.OfferedVersions
			if versions.UnmarshalData(ext.Data) != nil || !slices.Contains(versions.Versions, protocol.Version1_3) {
				return nil, 0, ErrUnsupported
			}
			ext.Data, err = (extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}}).MarshalData()
		case extension.TypeServerName:
			var name extension.ServerNameOffer
			err = name.UnmarshalData(ext.Data)
			nameLength = len(name.ServerName)
		}
		if err != nil {
			return nil, 0, err
		}
		innerExts = append(innerExts, ext)
	}
	innerExts = append(innerExts, extension.Raw{Type: extension.TypeEncryptedClientHello, Data: []byte{1}})
	if !validInnerExtensions(innerExts) {
		return nil, 0, ErrInvalid
	}

	return innerExts, nameLength, nil
}

func sealOuterClientHello(prefix []byte, innerExts []extension.Raw, config Config, suite CipherSuite, enc []byte, sender Sender, encoded, grease []byte) ([]byte, error) {
	outerPrefix := bytes.Clone(prefix)
	if len(enc) != 0 {
		_, _ = rand.Read(outerPrefix[2:34])
	}
	outerExts := slices.DeleteFunc(slices.Clone(innerExts), func(ext extension.Raw) bool {
		return ext.Type == extension.TypeEncryptedClientHello || ext.Type == extension.TypePreSharedKey
	})
	publicName, err := (extension.ServerNameOffer{ServerName: config.PublicName}).MarshalData()
	if err != nil {
		return nil, err
	}
	name := extension.Raw{Type: extension.TypeServerName, Data: publicName}
	if i := extensionIndex(outerExts, name.Type); i >= 0 {
		outerExts[i] = name
	} else {
		outerExts = append(outerExts, name)
	}
	offer := extension13.ECHClientHello{KDF: suite.KDFID, AEAD: suite.AEADID, ConfigID: config.ConfigID, Enc: enc, Payload: make([]byte, len(encoded)+16)}
	payload, err := offer.MarshalData()
	if err != nil {
		return nil, err
	}
	echIndex := len(outerExts)
	outerExts = append(outerExts, extension.Raw{Type: extension.TypeEncryptedClientHello, Data: payload})
	if grease != nil {
		outerExts = append(outerExts, extension.Raw{Type: extension.TypePreSharedKey, Data: grease})
	}
	aad, err := appendExtensions(bytes.Clone(outerPrefix), outerExts)
	if err != nil {
		return nil, err
	}
	offer.Payload, err = sender.Seal(aad, encoded)
	if err != nil {
		return nil, err
	}
	outerExts[echIndex].Data, err = offer.MarshalData()
	if err != nil {
		return nil, err
	}

	return appendExtensions(outerPrefix, outerExts)
}

// GREASE identities and binders conceal the real PSKs and retain their lengths.
// https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.2
func greasePSK(exts []extension.Raw) ([]byte, error) {
	i := extensionIndex(exts, extension.TypePreSharedKey)
	if i < 0 {
		return nil, nil
	}
	var offer extension13.OfferedPSKs
	if err := offer.UnmarshalData(bytes.Clone(exts[i].Data)); err != nil {
		return nil, err
	}
	for i := range offer.Identities {
		_, _ = rand.Read(offer.Identities[i].Identity)
		var age [4]byte
		_, _ = rand.Read(age[:])
		offer.Identities[i].ObfuscatedTicketAge = binary.BigEndian.Uint32(age[:])
	}
	for _, binder := range offer.Binders {
		_, _ = rand.Read(binder)
	}

	return offer.MarshalData()
}

// splitHello parses a DTLS ClientHello body, retaining exact wire bytes.
func splitHello(data []byte, padded bool) ([]byte, []extension.Raw, error) {
	wire, err := clienthello.Parse(data)
	if err != nil || len(wire.SessionID) > 32 || len(wire.CipherSuites) == 0 || !bytes.Equal(wire.Compression, []byte{1, 0}) {
		return nil, nil, ErrInvalid
	}
	if !padded && len(wire.Trailing) != 0 || len(bytes.Trim(wire.Trailing, "\x00")) != 0 {
		return nil, nil, ErrInvalid
	}
	if clienthello.ValidateExtensions(wire.Extensions, false) != nil {
		return nil, nil, ErrInvalid
	}

	return wire.Prefix, wire.Extensions, nil
}

// EncodeInnerClientHello clears the session ID and adds RFC 9849 section 6.1.3 padding.
// Compression is optional; callers may supply ECHOuterExtensions explicitly.
// nameLength is -1 when no server_name is present.
func EncodeInnerClientHello(inner []byte, maximumNameLength uint8, nameLength int) ([]byte, error) {
	_, exts, err := splitHello(inner, false)
	if err != nil || !hasInner(exts) || nameLength < -1 || nameLength > 65535 {
		return nil, ErrInvalid
	}
	sessionLen := int(inner[34])
	// ECH inners cannot offer DTLS 1.2
	if inner[35+sessionLen] != 0 {
		return nil, ErrInvalid
	}
	out := append(bytes.Clone(inner[:34]), 0)
	out = append(out, inner[35+sessionLen:]...)
	padding := max(0, int(maximumNameLength)-nameLength)
	if nameLength == -1 {
		padding = int(maximumNameLength) + 9
	}
	padding += (32 - (len(out)+padding)%32) % 32

	return append(out, make([]byte, padding)...), nil
}

func hasInner(exts []extension.Raw) bool {
	i := extensionIndex(exts, extension.TypeEncryptedClientHello)

	return i >= 0 && bytes.Equal(exts[i].Data, []byte{1})
}

func extensionIndex(exts []extension.Raw, typ extension.Type) int {
	return slices.IndexFunc(exts, func(e extension.Raw) bool { return e.Type == typ })
}

// OuterAAD replaces only the ciphertext payload with equal-length zeros.
// The input is a ClientHello body, without record or handshake headers.
func OuterAAD(outer []byte) ([]byte, error) {
	prefix, exts, err := splitHello(outer, false)
	if err != nil {
		return nil, err
	}
	i := extensionIndex(exts, extension.TypeEncryptedClientHello)
	var ech extension13.ECHClientHello
	if i < 0 || extensionIndex(exts, extension.TypeECHOuterExtensions) >= 0 ||
		ech.UnmarshalData(exts[i].Data) != nil || ech.Type != extension13.ECHClientHelloOuter {
		return nil, ErrInvalid
	}
	// Parse owns the extension bytes, and the validated payload is the final field.
	clear(exts[i].Data[len(exts[i].Data)-len(ech.Payload):])

	return appendExtensions(bytes.Clone(prefix), exts)
}

func appendExtensions(prefix []byte, exts []extension.Raw) ([]byte, error) {
	encoded, err := extension.MarshalRawList(exts)
	if err != nil {
		return nil, err
	}

	return append(prefix, encoded...), nil
}

// DecodeInnerClientHello validates padding and expands outer references in linear
// time, preserving their order and rejecting duplicates and forbidden references.
func DecodeInnerClientHello(encoded, outer []byte) ([]byte, error) {
	prefix, inner, err := splitHello(encoded, true)
	if err != nil || prefix[34] != 0 || prefix[35] != 0 || !hasInner(inner) {
		return nil, ErrInvalid
	}
	_, outerExts, err := splitHello(outer, false)
	if err != nil {
		return nil, err
	}
	expanded, err := expandOuterExtensions(inner, outerExts)
	if err != nil {
		return nil, err
	}
	if !validInnerExtensions(expanded) {
		return nil, ErrInvalid
	}
	out := bytes.Clone(prefix[:34])
	sessionLen := int(outer[34])
	out = append(out, outer[34:35+sessionLen]...)
	out = append(out, prefix[35:]...)

	return appendExtensions(out, expanded)
}

func expandOuterExtensions(inner, outerExts []extension.Raw) ([]extension.Raw, error) {
	if extensionIndex(outerExts, extension.TypeECHOuterExtensions) >= 0 {
		return nil, ErrInvalid
	}
	i := extensionIndex(inner, extension.TypeECHOuterExtensions)
	if i < 0 {
		return inner, nil
	}
	var refs extension13.ECHOuterExtensions
	if refs.UnmarshalData(inner[i].Data) != nil {
		return nil, ErrInvalid
	}
	expanded := make([]extension.Raw, 0, len(inner)-1+len(refs.Types))
	expanded = append(expanded, inner[:i]...)
	for _, typ := range refs.Types {
		next := extensionIndex(outerExts, typ)
		if next < 0 {
			return nil, ErrInvalid
		}
		expanded = append(expanded, outerExts[next])
		outerExts = outerExts[next+1:]
	}

	return append(expanded, inner[i+1:]...), nil
}

func validInnerExtensions(expanded []extension.Raw) bool {
	if clienthello.ValidateExtensions(expanded, true) != nil {
		return false
	}
	i := extensionIndex(expanded, extension.TypeSupportedVersions)
	var offered extension13.OfferedVersions
	if i < 0 || offered.UnmarshalData(expanded[i].Data) != nil {
		return false
	}

	return slices.Contains(offered.Versions, protocol.Version1_3) &&
		!slices.ContainsFunc(offered.Versions, func(v protocol.Version) bool { return v > protocol.Version1_3 })
}
