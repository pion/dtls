// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeExtensionListPreservesRawExtensions(t *testing.T) {
	rawExtensions := []extension.Raw{
		{Type: 0xfefe, Data: []byte{0x01, 0x02}},
		{Type: 0xfefe, Data: []byte{0x03}},
	}
	encoded, err := extension.MarshalRawList(rawExtensions)
	require.NoError(t, err)

	decoded, err := decodeExtensionList(encoded, extensionContextClientHello)
	require.NoError(t, err)
	require.Len(t, decoded, 2)
	assert.Equal(t, rawExtensions[0], decoded[0])
	assert.Equal(t, rawExtensions[1], decoded[1])

	roundTrip, err := extension.MarshalList(decoded)
	require.NoError(t, err)
	assert.Equal(t, encoded, roundTrip)
}

func TestDecodeExtensionListUsesMessageContext(t *testing.T) {
	selected := extension13.SelectedVersion{Version: protocol.Version1_3}
	encoded, err := extension.MarshalList([]extension.Value{selected})
	require.NoError(t, err)

	serverHello, err := decodeExtensionList(encoded, extensionContextServerHello13)
	require.NoError(t, err)
	require.IsType(t, &extension13.SelectedVersion{}, serverHello[0])

	_, err = decodeExtensionList(encoded, extensionContextClientHello)
	assert.Error(t, err)
}
