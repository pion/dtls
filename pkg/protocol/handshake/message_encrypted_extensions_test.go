// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"errors"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errMarshalEncryptedExtensionsTest = errors.New("marshal encrypted extensions test")

type failingEncryptedExtensionsExtension struct{}

func (f *failingEncryptedExtensionsExtension) Marshal() ([]byte, error) {
	return nil, errMarshalEncryptedExtensionsTest
}

func (f *failingEncryptedExtensionsExtension) Unmarshal([]byte) error {
	return nil
}

func (f *failingEncryptedExtensionsExtension) TypeValue() extension.TypeValue {
	return extension.ALPNTypeValue
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
			Extensions: []extension.Extension{
				&extension.ALPN{ProtocolNameList: []string{"h2", "http/1.1"}},
				&extension.UseExtendedMasterSecret{Supported: true},
			},
		}).Marshal()
		require.NoError(t, err)
		assert.Equal(t, []byte{
			0x00, 0x16, // extensions length
			0x00, 0x10, // ALPN
			0x00, 0x0e, // ALPN extension length
			0x00, 0x0c, // ALPN protocol name list length
			0x02, 0x68, 0x32, // h2
			0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, // http/1.1
			0x00, 0x17, // extended_master_secret
			0x00, 0x00, // extended_master_secret extension length
		}, raw)
	})

	t.Run("ExtensionMarshalError", func(t *testing.T) {
		raw, err := (&MessageEncryptedExtensions{
			Extensions: []extension.Extension{&failingEncryptedExtensionsExtension{}},
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
			0x00, 0x16, // extensions length
			0x00, 0x10, // ALPN
			0x00, 0x0e, // ALPN extension length
			0x00, 0x0c, // ALPN protocol name list length
			0x02, 0x68, 0x32, // h2
			0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, // http/1.1
			0x00, 0x17, // extended_master_secret
			0x00, 0x00, // extended_master_secret extension length
		})
		require.NoError(t, err)
		require.Len(t, msg.Extensions, 2)

		alpn, ok := msg.Extensions[0].(*extension.ALPN)
		require.True(t, ok)
		assert.Equal(t, []string{"h2", "http/1.1"}, alpn.ProtocolNameList)

		extendedMasterSecret, ok := msg.Extensions[1].(*extension.UseExtendedMasterSecret)
		require.True(t, ok)
		assert.True(t, extendedMasterSecret.Supported)
	})

	t.Run("ShortExtensionListHeader", func(t *testing.T) {
		previouslyParsedExts := []extension.Extension{
			&extension.UseExtendedMasterSecret{Supported: true},
		}
		msg := &MessageEncryptedExtensions{Extensions: previouslyParsedExts}

		err := msg.Unmarshal([]byte{0x00})
		assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)
		assert.Equal(t, previouslyParsedExts, msg.Extensions)
	})

	t.Run("MismatchedExtensionListLength", func(t *testing.T) {
		previouslyParsedExts := []extension.Extension{
			&extension.UseExtendedMasterSecret{Supported: true},
		}
		msg := &MessageEncryptedExtensions{Extensions: previouslyParsedExts}

		err := msg.Unmarshal([]byte{0x00, 0x01})
		assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)
		assert.Equal(t, previouslyParsedExts, msg.Extensions)
	})

	t.Run("ExtensionUnmarshalError", func(t *testing.T) {
		previouslyParsedExts := []extension.Extension{
			&extension.UseExtendedMasterSecret{Supported: true},
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
}
