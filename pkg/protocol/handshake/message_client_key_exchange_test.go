// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	types "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandshakeMessageClientKeyExchange(t *testing.T) {
	rawClientKeyExchange := []byte{0x20, 0x26, 0x78, 0x4a, 0x78, 0x70, 0xc1, 0xf9, 0x71, 0xea, 0x50, 0x4a, 0xb5, 0xbb, 0x00, 0x76, 0x02, 0x05, 0xda, 0xf7, 0xd0, 0x3f, 0xe3, 0xf7, 0x4e, 0x8a, 0x14, 0x6f, 0xb7, 0xe0, 0xc0, 0xff, 0x54}
	parsedClientKeyExchange := &MessageClientKeyExchange{PublicKey: rawClientKeyExchange[1:], KeyExchangeAlgorithm: types.KeyExchangeAlgorithmEcdhe}

	c := &MessageClientKeyExchange{
		KeyExchangeAlgorithm: types.KeyExchangeAlgorithmEcdhe,
	}
	assert.NoError(t, c.Unmarshal(rawClientKeyExchange))
	assert.Equal(t, parsedClientKeyExchange, c)

	raw, err := c.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawClientKeyExchange, raw)
}

func TestHandshakeMessageClientKeyExchange_ECDHEPSK(t *testing.T) {
	for _, test := range []struct {
		name      string
		data      []byte
		identity  []byte
		publicKey []byte
		wantErr   error
	}{
		{
			name: "empty identity without key length", data: []byte{0, 0},
			wantErr: dtlserrors.ErrBufferTooSmall,
		},
		{
			name: "identity consumes body", data: []byte{0, 1, 42},
			wantErr: dtlserrors.ErrBufferTooSmall,
		},
		{
			name: "truncated public key", data: []byte{0, 1, 42, 2, 1},
			wantErr: dtlserrors.ErrBufferTooSmall,
		},
		{
			name: "valid exchange", data: []byte{0, 1, 42, 2, 1, 2},
			identity: []byte{42}, publicKey: []byte{1, 2},
		},
		{
			name: "key excludes trailing bytes", data: []byte{0, 1, 42, 2, 1, 2, 99},
			identity: []byte{42}, publicKey: []byte{1, 2},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := &MessageClientKeyExchange{
				KeyExchangeAlgorithm: types.KeyExchangeAlgorithmPsk | types.KeyExchangeAlgorithmEcdhe,
			}
			err := message.Unmarshal(test.data)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)

				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.identity, message.IdentityHint)
			assert.Equal(t, test.publicKey, message.PublicKey)
		})
	}
}

func TestHandshakeMessageClientKeyExchange_PublicKeyTooLong(t *testing.T) {
	cert := &MessageClientKeyExchange{IdentityHint: []byte("identity"), PublicKey: make([]byte, 256), KeyExchangeAlgorithm: types.KeyExchangeAlgorithmEcdhe}

	raw, err := cert.Marshal()
	assert.ErrorIs(t, err, dtlserrors.ErrPublicKeyTooLong)
	assert.Nil(t, raw)

	out := make([]byte, cert.MarshalSize())
	for i := range out {
		out[i] = 0xaa
	}
	n, err := cert.MarshalTo(out)
	assert.ErrorIs(t, err, dtlserrors.ErrPublicKeyTooLong)
	assert.Zero(t, n)
	assert.NotContains(t, out, byte(0x00))
}
