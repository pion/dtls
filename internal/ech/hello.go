// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ech

import (
	"bytes"
	"crypto/rand"
	"slices"

	"github.com/pion/dtls/v4/internal/clienthello"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
)

// ClientContext retains the initial inner and outer bodies and HPKE state.
type ClientContext struct {
	Config       Config
	Suite        CipherSuite
	Sender       Sender
	Inner, Outer []byte
}

// NewClientHello constructs the initial ECH offer. PSK, early data, and retry.
func NewClientHello(configList, body []byte) (*ClientContext, error) {
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
	encoded, err := EncodeInnerClientHello(inner, config.MaxNameLength, nameLength)
	if err != nil {
		return nil, err
	}
	enc, sender, err := NewSender(*config, suite)
	if err != nil {
		return nil, err
	}
	outer, err := sealOuterClientHello(prefix, innerExts, *config, suite, enc, sender, encoded)
	if err != nil {
		return nil, err
	}

	return &ClientContext{Config: *config, Suite: suite, Sender: sender, Inner: inner, Outer: outer}, nil
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

func sealOuterClientHello(prefix []byte, innerExts []extension.Raw, config Config, suite CipherSuite, enc []byte, sender Sender, encoded []byte) ([]byte, error) {
	outerPrefix := bytes.Clone(prefix)
	if _, err := rand.Read(outerPrefix[2:34]); err != nil {
		return nil, err
	}
	outerExts := slices.Clone(innerExts[:len(innerExts)-1])
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
	outerExts = append(outerExts, extension.Raw{Type: extension.TypeEncryptedClientHello, Data: payload})
	aad, err := appendExtensions(bytes.Clone(outerPrefix), outerExts)
	if err != nil {
		return nil, err
	}
	offer.Payload, err = sender.Seal(aad, encoded)
	if err != nil {
		return nil, err
	}
	outerExts[len(outerExts)-1].Data, err = offer.MarshalData()
	if err != nil {
		return nil, err
	}

	return appendExtensions(outerPrefix, outerExts)
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
