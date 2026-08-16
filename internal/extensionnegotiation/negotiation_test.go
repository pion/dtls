// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extensionnegotiation

import (
	"bytes"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const unknownExtensionType extension.Type = 0xfefe

func clientHelloForTest(extensions ...extension.Value) *handshake.MessageClientHello {
	return &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		SessionID:          []byte{0x01, 0x02},
		CipherSuiteIDs:     []uint16{0x1301},
		CompressionMethods: []*protocol.CompressionMethod{{}},
		Extensions:         extensions,
	}
}

func requireAlert(t *testing.T, err error, description alert.Description) {
	t.Helper()

	var protocolAlert *alert.Alert
	require.ErrorAs(t, err, &protocolAlert)
	assert.Equal(t, description, protocolAlert.Description)
}

func TestFinalizeClientHelloDetachesHookValues(t *testing.T) {
	input := []byte{0x10}
	base := clientHelloForTest(extension.Raw{Type: unknownExtensionType, Data: input})
	var hookResult *handshake.MessageClientHello

	final, snapshot, err := FinalizeClientHello(base, func(ch handshake.MessageClientHello) handshake.Message {
		raw := ch.Extensions[0].(extension.Raw) //nolint:forcetypeassert
		raw.Data[0] = 0x20
		ch.Extensions[0] = raw
		hookResult = &ch

		return hookResult
	})
	require.NoError(t, err)
	assert.Equal(t, []byte{0x10}, input)

	hookRaw := hookResult.Extensions[0].(extension.Raw) //nolint:forcetypeassert
	hookRaw.Data[0] = 0xff
	finalRaw := final.Extensions[0].(extension.Raw) //nolint:forcetypeassert
	assert.Equal(t, []byte{0x20}, finalRaw.Data)
	snapshotRaw, ok := snapshot.Extension(unknownExtensionType)
	require.True(t, ok)
	assert.Equal(t, []byte{0x20}, snapshotRaw.Data)
}

func TestFinalizeClientHelloRejectsInvalidHookOutput(t *testing.T) {
	tests := []struct {
		name        string
		hook        func(handshake.MessageClientHello) handshake.Message
		want        error
		description alert.Description
	}{
		{
			name: "wrong message type",
			hook: func(handshake.MessageClientHello) handshake.Message {
				return &handshake.MessageServerHello{}
			},
			description: alert.InternalError,
		},
		{
			name: "typed nil message",
			hook: func(handshake.MessageClientHello) handshake.Message {
				return (*handshake.MessageClientHello)(nil)
			},
			description: alert.InternalError,
		},
		{
			name: "nil compression method",
			hook: func(ch handshake.MessageClientHello) handshake.Message {
				ch.CompressionMethods = []*protocol.CompressionMethod{nil}

				return &ch
			},
			description: alert.InternalError,
		},
		{
			name: "typed nil extension",
			hook: func(ch handshake.MessageClientHello) handshake.Message {
				ch.Extensions = []extension.Value{(*extension.ConnectionID)(nil)}

				return &ch
			},
			description: alert.InternalError,
		},
		{
			name: "duplicate extension",
			hook: func(ch handshake.MessageClientHello) handshake.Message {
				ch.Extensions = []extension.Value{&extension.ConnectionID{}, &extension.ConnectionID{}}

				return &ch
			},
			want:        dtlserrors.ErrDuplicateExtension,
			description: alert.IllegalParameter,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := FinalizeClientHello(clientHelloForTest(), test.hook)
			require.ErrorIs(t, err, dtlserrors.ErrInvalidClientHello)
			if test.want != nil {
				require.ErrorIs(t, err, test.want)
			}
			requireAlert(t, err, test.description)
		})
	}
}

func TestRecordWirePreservesExactClientHello(t *testing.T) {
	clientHello := clientHelloForTest(&extension12.SupportedPointFormats{
		PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed, 1},
	})
	clientHello.CompressionMethods = []*protocol.CompressionMethod{{ID: 0}, {ID: 0xfe}}
	raw, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	require.NoError(t, err)
	wantBody := bytes.Clone(raw[handshake.HeaderLength:])

	var history ClientHelloSnapshots
	require.NoError(t, history.RecordWire(raw))
	snapshot := history.Current()
	assert.Equal(t, wantBody, snapshot.body)
	pointFormats, ok := snapshot.Extension(extension.TypeSupportedPointFormats)
	require.True(t, ok)
	assert.Equal(t, []byte{2, 0, 1}, pointFormats.Data)

	raw[len(raw)-1] = 0xff
	assert.Equal(t, wantBody, snapshot.body)
}

func TestRecordWireRejectsWrongHandshakeType(t *testing.T) {
	raw, err := (&handshake.Handshake{Message: clientHelloForTest()}).Marshal()
	require.NoError(t, err)
	raw[0] = byte(handshake.TypeServerHello)

	var history ClientHelloSnapshots
	err = history.RecordWire(raw)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidClientHello)
	requireAlert(t, err, alert.DecodeError)
}

func TestClientHelloSnapshotsRetainInitialAndCurrentOffers(t *testing.T) {
	var history ClientHelloSnapshots
	for _, value := range []byte{0x01, 0x02} {
		_, snapshot, err := FinalizeClientHello(
			clientHelloForTest(extension.Raw{Type: unknownExtensionType, Data: []byte{value}}), nil,
		)
		require.NoError(t, err)
		history.Record(snapshot)
	}

	initial, ok := history.Initial().Extension(unknownExtensionType)
	require.True(t, ok)
	current, ok := history.Current().Extension(unknownExtensionType)
	require.True(t, ok)
	assert.Equal(t, []byte{0x01}, initial.Data)
	assert.Equal(t, []byte{0x02}, current.Data)

	initial.Data[0] = 0xff
	initial, _ = history.Initial().Extension(unknownExtensionType)
	assert.Equal(t, []byte{0x01}, initial.Data)
}
