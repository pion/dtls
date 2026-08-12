// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"bytes"
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// KeyShareEntry contains the encoded key exchange for a named group.
type KeyShareEntry struct {
	Group       elliptic.Curve
	KeyExchange []byte
}

// ClientKeyShare is the ClientHello key_share payload.
type ClientKeyShare struct {
	Shares []KeyShareEntry
}

// ExtensionType returns the IANA extension type.
func (ClientKeyShare) ExtensionType() extension.Type { return extension.TypeKeyShare }

// MarshalData encodes extension_data.
func (c ClientKeyShare) MarshalData() ([]byte, error) {
	entries, err := marshalKeyShareEntries(c.Shares, true)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 2, 2+len(entries))
	binary.BigEndian.PutUint16(out, uint16(len(entries))) //nolint:gosec // marshalKeyShareEntries bounds the length.
	out = append(out, entries...)

	return out, nil
}

// UnmarshalData decodes extension_data.
func (c *ClientKeyShare) UnmarshalData(data []byte) error {
	if len(data) < 2 || int(binary.BigEndian.Uint16(data)) != len(data)-2 {
		return dtlserrors.ErrInvalidKeyShareFormat
	}

	shares, err := unmarshalKeyShareEntries(data[2:])
	if err != nil {
		return err
	}
	c.Shares = shares

	return nil
}

// ServerKeyShare is the ServerHello key_share payload.
type ServerKeyShare struct {
	Share KeyShareEntry
}

// ExtensionType returns the IANA extension type.
func (ServerKeyShare) ExtensionType() extension.Type { return extension.TypeKeyShare }

// MarshalData encodes extension_data.
func (s ServerKeyShare) MarshalData() ([]byte, error) {
	return marshalKeyShareEntry(s.Share)
}

// UnmarshalData decodes extension_data.
func (s *ServerKeyShare) UnmarshalData(data []byte) error {
	shares, err := unmarshalKeyShareEntries(data)
	if err != nil || len(shares) != 1 {
		return dtlserrors.ErrInvalidKeyShareFormat
	}
	s.Share = shares[0]

	return nil
}

// RetryKeyShare is the HelloRetryRequest key_share payload.
type RetryKeyShare struct {
	SelectedGroup elliptic.Curve
}

// ExtensionType returns the IANA extension type.
func (RetryKeyShare) ExtensionType() extension.Type { return extension.TypeKeyShare }

// MarshalData encodes extension_data.
func (r RetryKeyShare) MarshalData() ([]byte, error) {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(r.SelectedGroup))

	return out, nil
}

// UnmarshalData decodes extension_data without filtering unknown groups.
func (r *RetryKeyShare) UnmarshalData(data []byte) error {
	if len(data) != 2 {
		return dtlserrors.ErrInvalidKeyShareFormat
	}
	r.SelectedGroup = elliptic.Curve(binary.BigEndian.Uint16(data))

	return nil
}

func marshalKeyShareEntries(entries []KeyShareEntry, allowEmpty bool) ([]byte, error) {
	if !allowEmpty && len(entries) == 0 {
		return nil, dtlserrors.ErrInvalidKeyShareFormat
	}

	out := make([]byte, 0)
	seen := make(map[elliptic.Curve]struct{}, len(entries))
	for _, entry := range entries {
		if _, ok := seen[entry.Group]; ok {
			return nil, dtlserrors.ErrDuplicateKeyShare
		}
		seen[entry.Group] = struct{}{}

		encoded, err := marshalKeyShareEntry(entry)
		if err != nil {
			return nil, err
		}
		if len(out) > 0xffff-len(encoded) {
			return nil, dtlserrors.ErrInvalidKeyShareFormat
		}
		out = append(out, encoded...)
	}

	return out, nil
}

func marshalKeyShareEntry(entry KeyShareEntry) ([]byte, error) {
	if len(entry.KeyExchange) == 0 || len(entry.KeyExchange) > 0xffff {
		return nil, dtlserrors.ErrInvalidKeyShareFormat
	}

	out := make([]byte, 4, 4+len(entry.KeyExchange))
	binary.BigEndian.PutUint16(out, uint16(entry.Group))
	binary.BigEndian.PutUint16(out[2:], uint16(len(entry.KeyExchange))) //nolint:gosec // length is bounded above.
	out = append(out, entry.KeyExchange...)

	return out, nil
}

func unmarshalKeyShareEntries(data []byte) ([]KeyShareEntry, error) {
	shares := make([]KeyShareEntry, 0)
	seen := map[elliptic.Curve]struct{}{}
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, dtlserrors.ErrInvalidKeyShareFormat
		}
		group := elliptic.Curve(binary.BigEndian.Uint16(data))
		length := int(binary.BigEndian.Uint16(data[2:]))
		data = data[4:]
		if length == 0 || length > len(data) {
			return nil, dtlserrors.ErrInvalidKeyShareFormat
		}
		if _, ok := seen[group]; ok {
			return nil, dtlserrors.ErrDuplicateKeyShare
		}
		seen[group] = struct{}{}
		shares = append(shares, KeyShareEntry{Group: group, KeyExchange: bytes.Clone(data[:length])})
		data = data[length:]
	}

	return shares, nil
}
