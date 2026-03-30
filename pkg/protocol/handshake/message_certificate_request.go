// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"crypto/tls"
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

/*
MessageCertificateRequest is so a non-anonymous server can optionally
request a certificate from the client, if appropriate for the selected cipher
suite.  This message, if sent, will immediately follow the ServerKeyExchange
message (if it is sent; otherwise, this message follows the
server's Certificate message).

https://tools.ietf.org/html/rfc5246#section-7.4.4
*/
type MessageCertificateRequest struct {
	CertificateTypes            []clientcertificate.Type
	SignatureHashAlgorithms     []signaturehash.Algorithm
	CertificateAuthoritiesNames [][]byte
}

const (
	messageCertificateRequestMinLength = 5
)

// Type returns the Handshake Type.
func (m MessageCertificateRequest) Type() Type {
	return TypeCertificateRequest
}

// Size returns the minimal size required for MarshalInto.
func (m *MessageCertificateRequest) Size() int {
	return 1 +
		len(m.CertificateTypes) +
		2 + // number of SignatureHashAlgorithms
		2*len(m.SignatureHashAlgorithms) + // SignatureHashAlgorithms size
		2 + // casLength
		m.casLength()
}

func (m *MessageCertificateRequest) casLength() int {
	casLength := 0
	for _, ca := range m.CertificateAuthoritiesNames {
		casLength += 2 + len(ca)
	}

	return casLength
}

// Marshal encodes the Handshake.
func (m *MessageCertificateRequest) Marshal() ([]byte, error) {
	out := make([]byte, m.Size())
	err := m.MarshalInto(out)

	return out, err
}

// MarshalInto encodes the Handshake into a pre-allocated buffer.
func (m *MessageCertificateRequest) MarshalInto(out []byte) error {
	if len(m.CertificateTypes) > 255 {
		return errCertificateTypesTooLong
	}

	if len(out) < m.Size() {
		return errBufferTooSmall
	}

	//nolint:gosec // G115: certificate types count is validated to be <= 255 above.
	offset := 0
	out[offset] = byte(len(m.CertificateTypes)) //nolint:gosec // G115
	offset += 1
	for _, v := range m.CertificateTypes {
		out[offset] = byte(v)
		offset += 1
	}

	binary.BigEndian.PutUint16(out[offset:], uint16(len(m.SignatureHashAlgorithms)*2)) //nolint:gosec //G115
	offset += 2

	for _, v := range m.SignatureHashAlgorithms {
		tmp := v.Marshal()
		n := copy(out[offset:], tmp)
		offset += n
	}

	// Distinguished Names
	binary.BigEndian.PutUint16(out[offset:], uint16(m.casLength())) //nolint:gosec //G115
	offset += 2
	if m.casLength() > 0 {
		for _, ca := range m.CertificateAuthoritiesNames {
			binary.BigEndian.PutUint16(out[offset:], uint16(len(ca))) //nolint:gosec //G115
			offset += 2
			n := copy(out[offset:], ca)
			offset += n
		}
	}

	return nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageCertificateRequest) Unmarshal(data []byte) error { //nolint:cyclop
	if len(data) < messageCertificateRequestMinLength {
		return errBufferTooSmall
	}

	offset := 0
	certificateTypesLength := int(data[0])
	offset++

	if (offset + certificateTypesLength) > len(data) {
		return errBufferTooSmall
	}

	for i := range certificateTypesLength {
		certType := clientcertificate.Type(data[offset+i])
		if _, ok := clientcertificate.Types()[certType]; ok {
			m.CertificateTypes = append(m.CertificateTypes, certType)
		}
	}
	offset += certificateTypesLength
	if len(data) < offset+2 {
		return errBufferTooSmall
	}
	signatureHashAlgorithmsLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if (offset + signatureHashAlgorithmsLength) > len(data) {
		return errBufferTooSmall
	}

	for i := 0; i < signatureHashAlgorithmsLength; i += 2 {
		if len(data) < (offset + i + 2) {
			return errBufferTooSmall
		}

		scheme := binary.BigEndian.Uint16(data[offset+i : offset+i+2])
		var alg signaturehash.Algorithm
		err := alg.Unmarshal(tls.SignatureScheme(scheme))
		if err != nil {
			return errInvalidSignHashAlgorithm
		}
		m.SignatureHashAlgorithms = append(m.SignatureHashAlgorithms, alg)
	}

	offset += signatureHashAlgorithmsLength
	if len(data) < offset+2 {
		return errBufferTooSmall
	}
	casLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if (offset + casLength) > len(data) {
		return errBufferTooSmall
	}
	cas := make([]byte, casLength)
	copy(cas, data[offset:offset+casLength])
	m.CertificateAuthoritiesNames = nil
	for len(cas) > 0 {
		if len(cas) < 2 {
			return errBufferTooSmall
		}
		caLen := binary.BigEndian.Uint16(cas)
		cas = cas[2:]

		if len(cas) < int(caLen) {
			return errBufferTooSmall
		}

		m.CertificateAuthoritiesNames = append(m.CertificateAuthoritiesNames, cas[:caLen])
		cas = cas[caLen:]
	}

	return nil
}
