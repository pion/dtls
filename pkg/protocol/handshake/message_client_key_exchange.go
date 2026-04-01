// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"encoding/binary"

	"github.com/pion/dtls/v3/internal/ciphersuite/types"
)

// MessageClientKeyExchange is a DTLS Handshake Message
// With this message, the premaster secret is set, either by direct
// transmission of the RSA-encrypted secret or by the transmission of
// Diffie-Hellman parameters that will allow each side to agree upon
// the same premaster secret.
//
// https://tools.ietf.org/html/rfc5246#section-7.4.7
type MessageClientKeyExchange struct {
	IdentityHint []byte
	PublicKey    []byte

	// for unmarshaling
	KeyExchangeAlgorithm types.KeyExchangeAlgorithm
}

// Type returns the Handshake Type.
func (m MessageClientKeyExchange) Type() Type {
	return TypeClientKeyExchange
}

// Marshal encodes the Handshake.
func (m *MessageClientKeyExchange) Marshal() ([]byte, error) {
	if m.IdentityHint == nil && m.PublicKey == nil {
		return nil, errInvalidClientKeyExchange
	}

	if m.PublicKey != nil {
		if len(m.PublicKey) > 255 {
			return nil, errPublicKeyTooLong
		}
	}

	out := make([]byte, m.Size())
	err := m.MarshalInto(out)

	return out, err
}

// Size returns the size required for MarshalInto.
func (m *MessageClientKeyExchange) Size() int {
	total := 0
	if m.IdentityHint != nil {
		total += 2
		total += len(m.IdentityHint)
	}

	if m.PublicKey != nil {
		total += 1
		total += len(m.PublicKey)
	}

	return total
}

// MarshalInto encodes the Handshake into a pre-allocated buffer.
func (m *MessageClientKeyExchange) MarshalInto(out []byte) error {
	if m.IdentityHint == nil && m.PublicKey == nil {
		return errInvalidClientKeyExchange
	}

	if len(out) < m.Size() {
		return errBufferTooSmall
	}

	offset := 0
	if m.IdentityHint != nil {
		binary.BigEndian.PutUint16(out[offset:], uint16(len(m.IdentityHint))) //nolint:gosec // G115
		offset += 2
		n := copy(out[offset:], m.IdentityHint)
		offset += n
	}

	if m.PublicKey != nil {
		if len(m.PublicKey) > 255 {
			return errPublicKeyTooLong
		}
		out[offset] = byte(len(m.PublicKey)) //nolint:gosec // G115: public key length is validated to be <= 255 above.
		offset += 1
		copy(out[offset:], m.PublicKey)
	}

	return nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageClientKeyExchange) Unmarshal(data []byte) error {
	switch {
	case len(data) < 2:
		return errBufferTooSmall
	case m.KeyExchangeAlgorithm == types.KeyExchangeAlgorithmNone:
		return errCipherSuiteUnset
	}

	offset := 0
	if m.KeyExchangeAlgorithm.Has(types.KeyExchangeAlgorithmPsk) {
		pskLength := int(binary.BigEndian.Uint16(data))
		if pskLength > len(data)-2 {
			return errBufferTooSmall
		}

		m.IdentityHint = append([]byte{}, data[2:pskLength+2]...)
		offset += pskLength + 2
	}

	if m.KeyExchangeAlgorithm.Has(types.KeyExchangeAlgorithmEcdhe) {
		publicKeyLength := int(data[offset])
		if publicKeyLength > len(data)-1-offset {
			return errBufferTooSmall
		}

		m.PublicKey = append([]byte{}, data[offset+1:]...)
	}

	return nil
}
