// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"testing"

	"github.com/pion/dtls/v4/pkg/protocol/extension"
	"github.com/stretchr/testify/require"
)

func TestECHExtension(t *testing.T) {
	for _, value := range []ECHClientHello{{Type: ECHClientHelloInner}, {KDF: 1, AEAD: 1, ConfigID: 2, Enc: []byte{3}, Payload: []byte{4}}, {KDF: 1, AEAD: 1, Enc: []byte{}, Payload: []byte{4}}} {
		data, err := value.MarshalData()
		require.NoError(t, err)
		require.Len(t, data, value.MarshalSize())
		var parsed ECHClientHello
		require.NoError(t, parsed.UnmarshalData(data))
		require.Equal(t, value, parsed)
		for i := range data {
			require.Error(t, parsed.UnmarshalData(data[:i]))
		}
		require.Error(t, parsed.UnmarshalData(append(data, 0)))
	}
	for _, data := range [][]byte{{2}, {1, 0}, {0}, {0, 0, 1, 0, 1, 0, 0, 0, 0, 0}} {
		var e ECHClientHello
		require.Error(t, e.UnmarshalData(data))
	}
	for _, types := range [][]extension.Type{nil, {1, 1}, {extension.TypeEncryptedClientHello}, {extension.TypeECHOuterExtensions}} {
		_, err := (ECHOuterExtensions{Types: types}).MarshalData()
		require.Error(t, err)
	}
	refs := ECHOuterExtensions{Types: []extension.Type{10, 51}}
	data, err := refs.MarshalData()
	require.NoError(t, err)
	var parsed ECHOuterExtensions
	require.NoError(t, parsed.UnmarshalData(data))
	require.Equal(t, refs, parsed)
	var hrr ECHHelloRetryRequest
	require.Error(t, hrr.UnmarshalData(make([]byte, 7)))
	require.NoError(t, hrr.UnmarshalData(make([]byte, 8)))
	var retry ECHRetryConfigs
	require.Error(t, retry.UnmarshalData([]byte{0, 0}))
	require.NoError(t, retry.UnmarshalData([]byte{0, 4, 0, 1, 0, 0}))
}

func FuzzECHClientHello(f *testing.F) {
	f.Add([]byte{1})
	f.Add([]byte{0, 0, 1, 0, 1, 7, 0, 0, 0, 1, 42})
	f.Fuzz(func(t *testing.T, data []byte) {
		var e ECHClientHello
		if e.UnmarshalData(data) != nil {
			return
		}
		encoded, err := e.MarshalData()
		require.NoError(t, err)
		require.Equal(t, data, encoded)
	})
}

func FuzzECHOuterExtensions(f *testing.F) {
	f.Add([]byte{4, 0, 10, 0, 51})
	f.Fuzz(func(t *testing.T, data []byte) {
		var e ECHOuterExtensions
		if e.UnmarshalData(data) != nil {
			return
		}
		encoded, err := e.MarshalData()
		require.NoError(t, err)
		require.Equal(t, data, encoded)
	})
}
