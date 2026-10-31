// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"fmt"
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/pkg/crypto/hash"
	"github.com/pion/dtls/v4/pkg/crypto/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandshakeMessageCertificateVerify(t *testing.T) {
	rawCertificateVerify := []byte{
		0x04, 0x03, 0x00, 0x47, 0x30, 0x45, 0x02, 0x20, 0x6b, 0x63, 0x17, 0xad, 0xbe, 0xb7, 0x7b, 0x0f,
		0x86, 0x73, 0x39, 0x1e, 0xba, 0xb3, 0x50, 0x9c, 0xce, 0x9c, 0xe4, 0x8b, 0xe5, 0x13, 0x07, 0x59,
		0x18, 0x1f, 0xe5, 0xa0, 0x2b, 0xca, 0xa6, 0xad, 0x02, 0x21, 0x00, 0xd3, 0xb5, 0x01, 0xbe, 0x87,
		0x6c, 0x04, 0xa1, 0xdc, 0x28, 0xaa, 0x5f, 0xf7, 0x1e, 0x9c, 0xc0, 0x1e, 0x00, 0x2c, 0xe5, 0x94,
		0xbb, 0x03, 0x0e, 0xf1, 0xcb, 0x28, 0x22, 0x33, 0x23, 0x88, 0xad,
	}
	parsedCertificateVerify := &MessageCertificateVerify{HashAlgorithm: hash.Algorithm(rawCertificateVerify[0]), SignatureAlgorithm: signature.Algorithm(rawCertificateVerify[1]), Signature: rawCertificateVerify[4:]}

	c := &MessageCertificateVerify{}
	assert.NoError(t, c.Unmarshal(rawCertificateVerify))
	assert.Equal(t, parsedCertificateVerify, c)

	raw, err := c.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawCertificateVerify, raw)
}

func TestHandshakeMessageCertificateVerifyPSS(t *testing.T) {
	for _, scheme := range []struct {
		signature signature.Algorithm
		hash      hash.Algorithm
		wire      byte
	}{
		{signature.RSA_PSS_RSAE_SHA256, hash.SHA256, 0x04},
		{signature.RSA_PSS_RSAE_SHA384, hash.SHA384, 0x05},
		{signature.RSA_PSS_RSAE_SHA512, hash.SHA512, 0x06},
		{signature.RSA_PSS_PSS_SHA256, hash.SHA256, 0x09},
		{signature.RSA_PSS_PSS_SHA384, hash.SHA384, 0x0a},
		{signature.RSA_PSS_PSS_SHA512, hash.SHA512, 0x0b},
	} {
		t.Run(fmt.Sprintf("%04x", scheme.signature), func(t *testing.T) {
			raw := []byte{0x08, scheme.wire, 0x00, 0x02, 0xaa, 0xbb}
			var message MessageCertificateVerify
			require.NoError(t, message.Unmarshal(raw))
			require.Equal(t, scheme.hash, message.HashAlgorithm)
			require.Equal(t, scheme.signature, message.SignatureAlgorithm)

			encoded, err := message.Marshal()
			require.NoError(t, err)
			require.Equal(t, raw, encoded)

			out := make([]byte, message.MarshalSize())
			n, err := message.MarshalTo(out)
			require.NoError(t, err)
			require.Equal(t, len(raw), n)
			require.Equal(t, raw, out)
		})
	}
}

func TestHandshakeMessageCertificateVerify_InvalidAlgorithmValue(t *testing.T) {
	for name, cert := range map[string]MessageCertificateVerify{
		"hash overflow":      {HashAlgorithm: hash.Algorithm(0x100), SignatureAlgorithm: signature.RSA},
		"signature overflow": {HashAlgorithm: hash.SHA256, SignatureAlgorithm: signature.Algorithm(0x100)},
		"PSS hash mismatch":  {HashAlgorithm: hash.SHA384, SignatureAlgorithm: signature.RSA_PSS_RSAE_SHA256},
	} {
		t.Run(name, func(t *testing.T) {
			cert.Signature = []byte{0x00}
			raw, err := cert.Marshal()
			assert.ErrorIs(t, err, dtlserrors.ErrInvalidSignHashAlgorithm)
			assert.Nil(t, raw)

			out := make([]byte, cert.MarshalSize())
			for i := range out {
				out[i] = 0xaa
			}
			n, err := cert.MarshalTo(out)
			assert.ErrorIs(t, err, dtlserrors.ErrInvalidSignHashAlgorithm)
			assert.Zero(t, n)
			assert.NotContains(t, out, byte(0x00))
		})
	}
}
