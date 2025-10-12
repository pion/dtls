// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/cryptobyte"
)

func TestSupportedGroups_Marshal_RoundTrip_OK(t *testing.T) {
	orig := &SupportedGroups{
		Groups: []NamedGroup{x448, x25519, secp256R1, ffdhe4096},
	}
	raw, err := orig.Marshal()
	assert.NoError(t, err)

	rd := cryptobyte.String(raw)
	var typ uint16
	assert.True(t, rd.ReadUint16(&typ), "failed to read type")
	assert.Equal(t, orig.TypeValue(), TypeValue(typ))

	var extData cryptobyte.String
	assert.True(t, rd.ReadUint16LengthPrefixed(&extData), "failed to read extData")

	var list cryptobyte.String
	assert.True(t, extData.ReadUint16LengthPrefixed(&list), "failed to read list")
	assert.True(t, extData.Empty(), "trailing bytes present in extData")

	var got []NamedGroup
	for !list.Empty() {
		var g uint16
		assert.True(t, list.ReadUint16(&g), "failed to read group")
		got = append(got, NamedGroup(g))
	}
	assert.Equal(t, len(orig.Groups), len(got))
	assert.Equal(t, orig.Groups, got)

	var parsed SupportedGroups
	err = parsed.Unmarshal(raw)
	assert.NoError(t, err)
	assert.Equal(t, orig.Groups, parsed.Groups)
}

func TestSupportedGroups_Marshal_Errors(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		sg := &SupportedGroups{Groups: nil}
		_, err := sg.Marshal()
		assert.ErrorIs(t, err, errInvalidSupportedGroupsFormat)
	})

	t.Run("invalid group present", func(t *testing.T) {
		sg := &SupportedGroups{Groups: []NamedGroup{x25519, 0x0001}} // 0x0001 is invalid
		_, err := sg.Marshal()
		assert.ErrorIs(t, err, errInvalidSupportedGroupsFormat)
	})
}

func TestSupportedGroups_Unmarshal_OK_IgnoresUnknown(t *testing.T) {
	// extension that includes: valid, invalid, valid.
	var b cryptobyte.Builder
	tv := SupportedGroups{}.TypeValue()
	b.AddUint16(uint16(tv))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(uint16(x25519))
			b.AddUint16(0x0001) // invalid, must be ignored
			b.AddUint16(uint16(secp384r1))
		})
	})
	raw, _ := b.Bytes()

	var sg SupportedGroups
	sg.Groups = []NamedGroup{ffdhe2048} // ensure slice is reset
	err := sg.Unmarshal(raw)
	assert.NoError(t, err)

	expected := []NamedGroup{x25519, secp384r1}
	assert.Equal(t, expected, sg.Groups)
}

func TestSupportedGroups_Unmarshal_Errors(t *testing.T) {
	// helper to make a basic header
	makeHeader := func(tt TypeValue, extPayload []byte) []byte {
		var b cryptobyte.Builder
		b.AddUint16(uint16(tt))
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(extPayload)
		})
		out, _ := b.Bytes()

		return out
	}

	t.Run("wrong extension type", func(t *testing.T) {
		raw := makeHeader(0xFFFF, []byte{0x00, 0x02, 0x00, 0x1D})

		var sg SupportedGroups
		err := sg.Unmarshal(raw)
		assert.ErrorIs(t, err, errInvalidExtensionType)
	})

	t.Run("buffer too small (no ext length present)", func(t *testing.T) {
		tv := SupportedGroups{}.TypeValue()
		raw := []byte{byte(tv >> 8), byte(tv)} // only 2-byte type

		var sg SupportedGroups
		err := sg.Unmarshal(raw)
		assert.ErrorIs(t, err, errBufferTooSmall)
	})

	t.Run("extData has trailing bytes after list", func(t *testing.T) {
		tv := SupportedGroups{}.TypeValue()
		var b cryptobyte.Builder
		b.AddUint16(uint16(tv))
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			// correct list with one element
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(uint16(x25519))
			})

			// extra trailing byte inside extData should result in an error
			b.AddUint8(0x00)
		})
		raw, _ := b.Bytes()

		var sg SupportedGroups
		err := sg.Unmarshal(raw)
		assert.ErrorIs(t, err, errInvalidSupportedGroupsFormat)
	})

	t.Run("list length prefix too short to contain uint16 length", func(t *testing.T) {
		// extData length = 1 byte, so extData.ReadUint16LengthPrefixed(&list) fails.
		typeValue := SupportedGroups{}.TypeValue()
		raw := makeHeader(typeValue, []byte{0x00}) // extData = 1 byte

		var sg SupportedGroups
		err := sg.Unmarshal(raw)
		assert.ErrorIs(t, err, errInvalidSupportedGroupsFormat)
	})

	t.Run("list has length < 2", func(t *testing.T) {
		tv := SupportedGroups{}.TypeValue()
		var b cryptobyte.Builder
		b.AddUint16(uint16(tv))

		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			// list len = 1 (odd and too small)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte{0x00})
			})
		})

		raw, _ := b.Bytes()

		var sg SupportedGroups
		err := sg.Unmarshal(raw)
		assert.ErrorIs(t, err, errInvalidSupportedGroupsFormat)
	})

	t.Run("list has odd length", func(t *testing.T) {
		typeValue := SupportedGroups{}.TypeValue()

		var b cryptobyte.Builder
		b.AddUint16(uint16(typeValue))
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			// list with 3 bytes -> odd -> error
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte{0x00, 0x1D, 0xFF})
			})
		})
		raw, _ := b.Bytes()

		var sg SupportedGroups
		err := sg.Unmarshal(raw)
		assert.ErrorIs(t, err, errInvalidSupportedGroupsFormat)
	})
}
