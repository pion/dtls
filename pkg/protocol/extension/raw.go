// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package extension provides TLS extension framing and payload codecs.
package extension

import (
	"bytes"
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

// Type is the two-byte value assigned to a TLS extension by IANA.
type Type uint16

const (
	TypeServerName              Type = 0
	TypeSupportedGroups         Type = 10
	TypeSupportedPointFormats   Type = 11
	TypeSignatureAlgorithms     Type = 13
	TypeUseSRTP                 Type = 14
	TypeALPN                    Type = 16
	TypePadding                 Type = 21
	TypeExtendedMasterSecret    Type = 23
	TypePreSharedKey            Type = 41
	TypeEarlyData               Type = 42
	TypeSupportedVersions       Type = 43
	TypeCookie                  Type = 44
	TypePSKKeyExchangeModes     Type = 45
	TypeCertificateAuthorities  Type = 47
	TypeOIDFilters              Type = 48
	TypePostHandshakeAuth       Type = 49
	TypeSignatureAlgorithmsCert Type = 50
	TypeKeyShare                Type = 51
	TypeConnectionID            Type = 54
	TypeReturnRoutabilityCheck  Type = 61
	TypeRenegotiationInfo       Type = 65281
)

// Value is an extension payload that can be framed in an extension list.
type Value interface {
	ExtensionType() Type
	MarshalData() ([]byte, error)
}

// CachedList is a list of extensions that can be cached.
type CachedList struct {
	Values                  []Value // Never access this field directly
	marshalledExtensions    []byte
	marshalledExtensionsErr error
}

func (l *CachedList) MarshalSize() int {
	err := l.cache()
	if err != nil {
		return 0
	}

	return len(l.marshalledExtensions)
}

func (l *CachedList) MarshalTo(out []byte) (int, error) {
	err := l.cache()
	if err != nil {
		return 0, err
	}
	if len(out) < l.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	return copy(out, l.marshalledExtensions), nil
}

func (l *CachedList) cache() error {
	if l.marshalledExtensions == nil && l.marshalledExtensionsErr == nil {
		l.marshalledExtensions, l.marshalledExtensionsErr = MarshalList(l.Values)
	}

	return l.marshalledExtensionsErr
}

// PayloadUnmarshaller decodes extension_data without the extension header.
type PayloadUnmarshaller interface {
	UnmarshalData(data []byte) error
}

// Raw is a lossless representation of an extension whose payload has not
// been decoded. Data does not include the type or length fields.
type Raw struct {
	Type Type
	Data []byte
}

// ExtensionType returns the extension type.
func (r Raw) ExtensionType() Type { return r.Type }

// MarshalData returns a copy of the undecoded payload.
func (r Raw) MarshalData() ([]byte, error) { return bytes.Clone(r.Data), nil }

// UnmarshalData replaces the undecoded payload with a copy of data.
func (r *Raw) UnmarshalData(data []byte) error {
	r.Data = bytes.Clone(data)

	return nil
}

// ParseList parses a complete uint16-length-prefixed extension list. It
// validates framing only and preserves unknown extensions, order, and
// duplicates for contextual processing by the caller.
func ParseList(buf []byte) ([]Raw, error) {
	if len(buf) < 2 {
		return nil, dtlserrors.ErrBufferTooSmall
	}

	declaredLen := int(binary.BigEndian.Uint16(buf))
	if declaredLen != len(buf)-2 {
		return nil, dtlserrors.ErrLengthMismatch
	}

	values := make([]Raw, 0)
	for offset := 2; offset < len(buf); {
		if len(buf)-offset < 4 {
			return nil, dtlserrors.ErrBufferTooSmall
		}

		typ := Type(binary.BigEndian.Uint16(buf[offset:]))
		payloadLen := int(binary.BigEndian.Uint16(buf[offset+2:]))
		offset += 4
		if payloadLen > len(buf)-offset {
			return nil, dtlserrors.ErrLengthMismatch
		}

		values = append(values, Raw{
			Type: typ,
			Data: bytes.Clone(buf[offset : offset+payloadLen]),
		})
		offset += payloadLen
	}

	return values, nil
}

// MarshalList frames extension payloads as a uint16-length-prefixed list.
func MarshalList(values []Value) ([]byte, error) {
	payloads := make([][]byte, len(values))
	totalLen := 0
	for i, value := range values {
		if value == nil {
			return nil, dtlserrors.ErrNilExtension
		}

		payload, err := value.MarshalData()
		if err != nil {
			return nil, err
		}
		if len(payload) > 0xffff || totalLen > 0xffff-4-len(payload) {
			return nil, dtlserrors.ErrInvalidExtensionsLength
		}

		payloads[i] = payload
		totalLen += 4 + len(payload)
	}

	out := make([]byte, 2, 2+totalLen)
	binary.BigEndian.PutUint16(out, uint16(totalLen)) //nolint:gosec // totalLen is bounded above.
	for i, value := range values {
		out = binary.BigEndian.AppendUint16(out, uint16(value.ExtensionType()))
		out = binary.BigEndian.AppendUint16(out, uint16(len(payloads[i]))) //nolint:gosec // bounded above.
		out = append(out, payloads[i]...)
	}

	return out, nil
}

// MarshalRawList frames raw extensions without decoding their payloads.
func MarshalRawList(values []Raw) ([]byte, error) {
	typed := make([]Value, len(values))
	for i := range values {
		typed[i] = values[i]
	}

	return MarshalList(typed)
}
