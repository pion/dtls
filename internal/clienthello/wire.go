// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package clienthello parses DTLS ClientHello framing.
package clienthello

import (
	"encoding/binary"
	"fmt"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	"golang.org/x/crypto/cryptobyte"
)

// Wire retains the original ClientHello fields. Byte slices reference the input;
// extension payloads are owned copies, as returned by extension.ParseList.
type Wire struct {
	// Prefix contains everything before the extensions vector.
	Prefix       []byte
	SessionID    []byte
	Cookie       []byte
	CipherSuites []uint16
	// Compression includes its length prefix for the protocol decoder.
	Compression []byte
	Extensions  []extension.Raw
	Trailing    []byte
}

// ValidateExtensions rejects duplicate types and optionally requires
// pre_shared_key to be last. Encoded ECH inners defer ordering until expansion.
func ValidateExtensions(extensions []extension.Raw, requirePSKLast bool) error {
	seen := make(map[extension.Type]bool, len(extensions))
	for _, ext := range extensions {
		if seen[ext.Type] {
			return fmt.Errorf("extension %d: %w", ext.Type, dtlserrors.ErrDuplicateExtension)
		}
		seen[ext.Type] = true
	}
	if requirePSKLast && seen[extension.TypePreSharedKey] && extensions[len(extensions)-1].Type != extension.TypePreSharedKey {
		return fmt.Errorf("extension %d: %w", extension.TypePreSharedKey, dtlserrors.ErrPreSharedKeyNotLast)
	}

	return nil
}

// Parse parses one ClientHello body without record or handshake headers.
// It leaves trailing bytes are handled by the caller because ECH interprets
// them as inner-hello padding.
func Parse(data []byte) (Wire, error) {
	input := cryptobyte.String(data)
	var session, cookie, suites, compression, extensions cryptobyte.String
	if !input.Skip(34) || !input.ReadUint8LengthPrefixed(&session) ||
		!input.ReadUint8LengthPrefixed(&cookie) || !input.ReadUint16LengthPrefixed(&suites) {
		return Wire{}, dtlserrors.ErrBufferTooSmall
	}
	if len(suites)%2 != 0 {
		return Wire{}, dtlserrors.ErrLengthMismatch
	}
	ids := make([]uint16, len(suites)/2)
	for i := range ids {
		ids[i] = binary.BigEndian.Uint16(suites[2*i:])
	}
	compressionStart := input
	if !input.ReadUint8LengthPrefixed(&compression) {
		return Wire{}, dtlserrors.ErrBufferTooSmall
	}
	extensionsStart := input
	if !input.ReadUint16LengthPrefixed(&extensions) {
		return Wire{}, dtlserrors.ErrBufferTooSmall
	}
	raw, err := extension.ParseList(extensionsStart[:2+len(extensions)])
	if err != nil {
		return Wire{}, err
	}

	return Wire{
		Prefix:    data[:len(data)-len(extensionsStart)],
		SessionID: session, Cookie: cookie,
		CipherSuites: ids,
		Compression:  compressionStart[:1+len(compression)],
		Extensions:   raw, Trailing: input,
	}, nil
}
