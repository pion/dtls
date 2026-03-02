// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"crypto/x509"
	"math"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/stretchr/testify/assert"
)

func TestCertificateAuth(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	assert.NoError(t, err)

	subject := certificate.RawSubject
	lenSub := len(subject)

	extension := CertificateAuthorities{Authorities: [][]byte{subject}}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x2f, // extension type
		0x00, byte(lenSub + 4), // extension length
		0x00, byte(lenSub + 2), // subjects length
		0x00, byte(lenSub), // subject length

	}
	expect = append(expect, subject...)

	assert.Equal(t, expect, raw)

	newExtension := CertificateAuthorities{}

	assert.NoError(t, newExtension.Unmarshal(expect))
	assert.Equal(t, extension.Authorities, newExtension.Authorities)
}

func TestCertificateAuth_Multiple(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	assert.NoError(t, err)

	subject := certificate.RawSubject
	lenSub := len(subject)

	extension := CertificateAuthorities{Authorities: [][]byte{subject, subject}}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x2f, // extension type
		0x00, byte(lenSub*2 + 6), // extension length
		0x00, byte(lenSub*2 + 4), // subjects length
		0x00, byte(lenSub), // subject length
	}
	expect = append(expect, subject...)
	expect = append(expect, []byte{0x00, byte(lenSub)}...)
	expect = append(expect, subject...)

	assert.Equal(t, expect, raw)

	newExtension := CertificateAuthorities{}

	assert.NoError(t, newExtension.Unmarshal(expect))
	assert.Equal(t, extension.Authorities, newExtension.Authorities)
}

func TestCertificateAuth_Empty(t *testing.T) {
	extension := CertificateAuthorities{Authorities: [][]byte{}}

	_, err := extension.Marshal()
	assert.Error(t, err)

	raw := []byte{
		0x00, 0x2f, // extension type
		0x00, 0x02, // extension length
		0x00, 0x00, // empty subjects
	}

	newExtension := CertificateAuthorities{}

	assert.Error(t, newExtension.Unmarshal(raw))
}

func FuzzCertificateAuthUnmarshal(f *testing.F) {
	cert, _ := selfsign.GenerateSelfSigned()
	certificate, _ := x509.ParseCertificate(cert.Certificate[0])
	subject := certificate.RawSubject
	lenSub := len(subject)

	raw := []byte{
		0x00, 0x2f, // extension type
		0x00, byte(lenSub*2 + 6), // extension length
		0x00, byte(lenSub*2 + 4), // subjects length
		0x00, byte(lenSub), // subject length
	}
	raw = append(raw, subject...)
	raw = append(raw, []byte{0x00, byte(lenSub)}...)
	raw = append(raw, subject...)

	testcases := [][]byte{
		{
			0x00, 0x2f, // extension type
			0x00, 0x02, // extension length
			0x00, 0x00, // empty subjects
		},
		raw,
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, a []byte) {
		certAuth := CertificateAuthorities{}
		err := certAuth.Unmarshal(a)
		if err == nil {
			length := len(certAuth.Authorities)
			assert.NotZero(t, length)
			assert.LessOrEqual(t, length, math.MaxUint16)
		}
	})
}
