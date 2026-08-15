// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"errors"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errMarshalEncryptedExtensionsTest = errors.New("marshal encrypted extensions test")

const unknownEncryptedExtensionsType extension.Type = 0xfefe

type failingEncryptedExtensionsExtension struct{}

func (f *failingEncryptedExtensionsExtension) MarshalData() ([]byte, error) {
	return nil, errMarshalEncryptedExtensionsTest
}

func (f *failingEncryptedExtensionsExtension) ExtensionType() extension.Type {
	return extension.TypeALPN
}

func TestMessageEncryptedExtensionsType(t *testing.T) {
	msg := &MessageEncryptedExtensions{}
	assert.Equal(t, TypeEncryptedExtensions, msg.Type())
}

func TestMessageEncryptedExtensionsMarshal(t *testing.T) {
	t.Run("NoExtensions", func(t *testing.T) {
		raw, err := (&MessageEncryptedExtensions{}).Marshal()
		require.NoError(t, err)
		assert.Equal(t, []byte{0x00, 0x00}, raw)
	})

	t.Run("WithExtensions", func(t *testing.T) {
		raw, err := (&MessageEncryptedExtensions{
			Extensions: []extension.Value{
				&extension.ALPNSelection{Protocol: "h2"},
				extension.Raw{Type: unknownEncryptedExtensionsType},
			},
		}).Marshal()
		require.NoError(t, err)
		assert.Equal(t, []byte{
			0x00, 0x0d, // extensions length
			0x00, 0x10, // ALPN
			0x00, 0x05, // ALPN extension length
			0x00, 0x03, // ALPN protocol name list length
			0x02, 0x68, 0x32, // h2
			0xfe, 0xfe, // unknown extension
			0x00, 0x00, // unknown extension length
		}, raw)
	})

	t.Run("ExtensionMarshalError", func(t *testing.T) {
		raw, err := (&MessageEncryptedExtensions{
			Extensions: []extension.Value{&failingEncryptedExtensionsExtension{}},
		}).Marshal()
		assert.ErrorIs(t, err, errMarshalEncryptedExtensionsTest)
		assert.Nil(t, raw)
	})
}

func TestMessageEncryptedExtensionsUnmarshal(t *testing.T) {
	t.Run("EmptyExtensionList", func(t *testing.T) {
		msg := &MessageEncryptedExtensions{}

		err := msg.Unmarshal([]byte{0x00, 0x00})
		require.NoError(t, err)
		assert.Empty(t, msg.Extensions)
	})

	t.Run("ZeroLengthBuffer", func(t *testing.T) {
		msg := &MessageEncryptedExtensions{}

		err := msg.Unmarshal([]byte{})
		require.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)
		assert.Empty(t, msg.Extensions)
	})

	t.Run("WithExtensions", func(t *testing.T) {
		msg := &MessageEncryptedExtensions{}

		err := msg.Unmarshal([]byte{
			0x00, 0x0d, // extensions length
			0x00, 0x10, // ALPN
			0x00, 0x05, // ALPN extension length
			0x00, 0x03, // ALPN protocol name list length
			0x02, 0x68, 0x32, // h2
			0xfe, 0xfe, // unknown extension
			0x00, 0x00, // unknown extension length
		})
		require.NoError(t, err)
		require.Len(t, msg.Extensions, 2)

		alpn, ok := msg.Extensions[0].(*extension.ALPNSelection)
		require.True(t, ok)
		assert.Equal(t, "h2", alpn.Protocol)

		unknown, ok := msg.Extensions[1].(extension.Raw)
		require.True(t, ok)
		assert.Equal(t, unknownEncryptedExtensionsType, unknown.Type)
	})

	t.Run("ShortExtensionListHeader", func(t *testing.T) {
		previouslyParsedExts := []extension.Value{
			extension.Raw{Type: unknownEncryptedExtensionsType},
		}
		msg := &MessageEncryptedExtensions{Extensions: previouslyParsedExts}

		err := msg.Unmarshal([]byte{0x00})
		assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)
		assert.Equal(t, previouslyParsedExts, msg.Extensions)
	})

	t.Run("MismatchedExtensionListLength", func(t *testing.T) {
		previouslyParsedExts := []extension.Value{
			extension.Raw{Type: unknownEncryptedExtensionsType},
		}
		msg := &MessageEncryptedExtensions{Extensions: previouslyParsedExts}

		err := msg.Unmarshal([]byte{0x00, 0x01})
		assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)
		assert.Equal(t, previouslyParsedExts, msg.Extensions)
	})

	t.Run("ExtensionUnmarshalError", func(t *testing.T) {
		previouslyParsedExts := []extension.Value{
			extension.Raw{Type: unknownEncryptedExtensionsType},
		}
		msg := &MessageEncryptedExtensions{Extensions: previouslyParsedExts}

		err := msg.Unmarshal([]byte{
			0x00, 0x06, // extensions length
			0x00, 0x10, // ALPN
			0x00, 0x02, // ALPN extension length
			0x00, 0x00, // empty ALPN protocol name list
		})
		assert.ErrorIs(t, err, extension.ErrALPNInvalidFormat)
		assert.Equal(t, previouslyParsedExts, msg.Extensions)
	})

	t.Run("KnownIllegalExtension", func(t *testing.T) {
		msg := &MessageEncryptedExtensions{}
		err := msg.Unmarshal([]byte{
			0x00, 0x04,
			0x00, 0x17,
			0x00, 0x00,
		})
		assert.ErrorIs(t, err, dtlserrors.ErrExtensionNotAllowed)
		var got *alert.Alert
		require.ErrorAs(t, err, &got)
		assert.Equal(t, alert.IllegalParameter, got.Description)
		assert.Empty(t, msg.Extensions)
	})
}
