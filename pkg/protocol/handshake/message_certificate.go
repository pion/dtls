// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/internal/util"
)

// MessageCertificate is a DTLS Handshake Message
// it can contain either a Client or Server Certificate
//
// https://tools.ietf.org/html/rfc5246#section-7.4.2
type MessageCertificate struct {
	Certificate [][]byte
}

// Type returns the Handshake Type.
func (m MessageCertificate) Type() Type {
	return TypeCertificate
}

const (
	handshakeMessageCertificateLengthFieldSize = 3
)

// MarshalSize returns the minimal size required for MarshalTo.
func (m *MessageCertificate) MarshalSize() int {
	total := handshakeMessageCertificateLengthFieldSize

	for _, cert := range m.Certificate {
		total += handshakeMessageCertificateLengthFieldSize + len(cert)
	}

	return total
}

// Marshal encodes the Handshake.
func (m *MessageCertificate) Marshal() ([]byte, error) {
	out := make([]byte, m.MarshalSize())
	_, err := m.MarshalTo(out)

	return out, err
}

// MarshalTo encodes the Handshake into a pre-allocated buffer.
func (m *MessageCertificate) MarshalTo(out []byte) (int, error) {
	if len(out) < m.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}
	// Total Payload MarshalSize
	//nolint:gosec // G115
	util.PutBigEndianUint24(out, uint32(m.MarshalSize()-handshakeMessageCertificateLengthFieldSize))
	offset := handshakeMessageCertificateLengthFieldSize

	for _, cert := range m.Certificate {
		// Certificate Length
		//nolint:gosec // G115
		util.PutBigEndianUint24(out[offset:], uint32(len(cert)))
		offset += handshakeMessageCertificateLengthFieldSize

		// Certificate body
		offset += copy(out[offset:], cert)
	}

	return m.MarshalSize(), nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageCertificate) Unmarshal(data []byte) error {
	if len(data) < handshakeMessageCertificateLengthFieldSize {
		return dtlserrors.ErrBufferTooSmall
	}

	if certificateBodyLen := int(util.BigEndianUint24(
		data,
	)); certificateBodyLen+handshakeMessageCertificateLengthFieldSize != len(data) {
		return dtlserrors.ErrLengthMismatch
	}

	offset := handshakeMessageCertificateLengthFieldSize
	for offset < len(data) {
		certificateLen := int(util.BigEndianUint24(data[offset:]))
		offset += handshakeMessageCertificateLengthFieldSize

		if offset+certificateLen > len(data) {
			return dtlserrors.ErrLengthMismatch
		}

		m.Certificate = append(m.Certificate, bytes.Clone(data[offset:offset+certificateLen]))
		offset += certificateLen
	}

	return nil
}
