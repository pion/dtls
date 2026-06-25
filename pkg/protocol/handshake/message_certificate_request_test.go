// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/stretchr/testify/assert"
)

func TestHandshakeMessageCertificateRequest(t *testing.T) {
	cases := map[string]struct {
		rawCertificateRequest    []byte
		parsedCertificateRequest *MessageCertificateRequest
		expErr                   error
	}{
		"valid - with CertificateAuthoritiesNames": {
			rawCertificateRequest: []byte{
				0x02, 0x01, 0x40, 0x00, 0x0C, 0x04, 0x03, 0x04, 0x01, 0x05,
				0x03, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x00, 0x06, 0x00,
				0x04, 0x74, 0x65, 0x73, 0x74,
			},
			parsedCertificateRequest: &MessageCertificateRequest{
				CertificateTypes: []clientcertificate.Type{
					clientcertificate.RSASign,
					clientcertificate.ECDSASign,
				},
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
					{Hash: hash.SHA256, Signature: signature.RSA},
					{Hash: hash.SHA384, Signature: signature.ECDSA},
					{Hash: hash.SHA384, Signature: signature.RSA},
					{Hash: hash.SHA512, Signature: signature.RSA},
					{Hash: hash.SHA1, Signature: signature.RSA},
				},
				CertificateAuthoritiesNames: [][]byte{[]byte("test")},
			},
		},
		"valid - without CertificateAuthoritiesNames": {
			rawCertificateRequest: []byte{
				0x02, 0x01, 0x40, 0x00, 0x0C, 0x04, 0x03, 0x04, 0x01, 0x05,
				0x03, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x00, 0x00,
			},
			parsedCertificateRequest: &MessageCertificateRequest{
				CertificateTypes: []clientcertificate.Type{
					clientcertificate.RSASign,
					clientcertificate.ECDSASign,
				},
				SignatureHashAlgorithms: []signaturehash.Algorithm{
					{Hash: hash.SHA256, Signature: signature.ECDSA},
					{Hash: hash.SHA256, Signature: signature.RSA},
					{Hash: hash.SHA384, Signature: signature.ECDSA},
					{Hash: hash.SHA384, Signature: signature.RSA},
					{Hash: hash.SHA512, Signature: signature.RSA},
					{Hash: hash.SHA1, Signature: signature.RSA},
				},
			},
		},
		"invalid - casLength CertificateAuthoritiesNames": {
			rawCertificateRequest: []byte{
				0x02, 0x01, 0x40, 0x00, 0x0C, 0x04, 0x03, 0x04, 0x01, 0x05,
				0x03, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x01,
			},
			expErr: dtlserrors.ErrBufferTooSmall,
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			c := &MessageCertificateRequest{}
			err := c.Unmarshal(testCase.rawCertificateRequest)

			if testCase.expErr != nil {
				assert.ErrorIs(t, err, testCase.expErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, testCase.parsedCertificateRequest, c)

				raw, err := c.Marshal()
				assert.NoError(t, err)
				assert.Equal(t, testCase.rawCertificateRequest, raw)
			}
		})
	}
}

// verify unrecognized signature algorithm pairs in a CertificateRequest are silently
// skipped rather than causing a handshake failure.
func TestHandshakeMessageCertificateRequest_SkipsUnknownAlgorithms(t *testing.T) {
	raw := []byte{
		0x02,       // cert types length: 2
		0x01, 0x40, // RSASign, ECDSASign
		0x00, 0x0C, // sig algs length: 12 bytes (6 pairs)
		0x04, 0x03, // SHA256+ECDSA  (valid)
		0x04, 0x01, // SHA256+RSA    (valid)
		0x04, 0x02, // SHA256+DSA    (unknown, skip) — Firefox 0x0402
		0x05, 0x02, // SHA384+DSA    (unknown, skip) — Firefox 0x0502
		0x06, 0x02, // SHA512+DSA    (unknown, skip) — Firefox 0x0602
		0x02, 0x02, // SHA1+DSA      (unknown, skip) — Firefox 0x0202
		0x00, 0x00, // CAs length: 0
	}

	c := &MessageCertificateRequest{}
	assert.NoError(t, c.Unmarshal(raw))
	assert.Equal(t, []signaturehash.Algorithm{
		{Hash: hash.SHA256, Signature: signature.ECDSA},
		{Hash: hash.SHA256, Signature: signature.RSA},
	}, c.SignatureHashAlgorithms)
}

func TestHandshakeMessageCertificateRequest_CertificateTypesTooLong(t *testing.T) {
	c := &MessageCertificateRequest{
		CertificateTypes: make([]clientcertificate.Type, 256),
	}

	_, err := c.Marshal()
	assert.ErrorIs(t, err, dtlserrors.ErrCertificateTypesTooLong)
}
