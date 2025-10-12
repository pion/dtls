// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/cryptobyte"
)

func TestKeyShare_Marshal_ClientHello_EmptyVector_RoundTrip(t *testing.T) {
	// No fields set -> treated as ClientHello with empty client_shares vector
	var ks KeyShare
	raw, err := ks.Marshal()
	assert.NoError(t, err)

	// Expect: type, ext_len=2, vector_len=0
	typeValue := ks.TypeValue()
	expect := []byte{byte(uint16(typeValue) >> 8), byte(uint16(typeValue)), 0x00, 0x02, 0x00, 0x00}
	assert.Equal(t, expect, raw)

	var parsed KeyShare
	err = parsed.Unmarshal(raw)
	assert.NoError(t, err)
	assert.Nil(t, parsed.ServerShare)
	assert.Nil(t, parsed.SelectedGroup)
	assert.Equal(t, 0, len(parsed.ClientShares))
}

func TestKeyShare_Marshal_ClientHello_OK(t *testing.T) {
	p1 := bytes.Repeat([]byte{0x01}, 32) // pretend X25519 public key
	p2 := bytes.Repeat([]byte{0x02}, 65) // pretend P-256 uncompressed point

	ks := &KeyShare{
		ClientShares: []KeyShareEntry{
			{Group: x25519, KeyExchange: p1},
			{Group: secp256R1, KeyExchange: p2},
		},
	}

	raw, err := ks.Marshal()
	assert.NoError(t, err)

	var parsed KeyShare
	err = parsed.Unmarshal(raw)
	assert.NoError(t, err)

	assert.Nil(t, parsed.ServerShare)
	assert.Nil(t, parsed.SelectedGroup)
	assert.Equal(t, 2, len(parsed.ClientShares))
	assert.Equal(t, x25519, parsed.ClientShares[0].Group)
	assert.Equal(t, p1, parsed.ClientShares[0].KeyExchange)
	assert.Equal(t, secp256R1, parsed.ClientShares[1].Group)
	assert.Equal(t, p2, parsed.ClientShares[1].KeyExchange)
}

func TestKeyShare_Marshal_ClientHello_Errors(t *testing.T) {
	t.Run("invalid group", func(t *testing.T) {
		ks := &KeyShare{
			ClientShares: []KeyShareEntry{{Group: 0x0001, KeyExchange: []byte{1}}},
		}

		_, err := ks.Marshal()
		assert.ErrorIs(t, err, errInvalidKeyShareGroup)
	})

	t.Run("duplicate group", func(t *testing.T) {
		ks := &KeyShare{
			ClientShares: []KeyShareEntry{
				{Group: x25519, KeyExchange: []byte{1}},
				{Group: x25519, KeyExchange: []byte{2}},
			},
		}

		_, err := ks.Marshal()
		assert.ErrorIs(t, err, errDuplicateKeyShare)
	})

	t.Run("key len = 0", func(t *testing.T) {
		ks := &KeyShare{
			ClientShares: []KeyShareEntry{
				{Group: x25519, KeyExchange: nil},
			},
		}

		_, err := ks.Marshal()
		assert.ErrorIs(t, err, errInvalidKeyShareFormat)
	})

	t.Run("key len > 65535", func(t *testing.T) {
		ks := &KeyShare{
			ClientShares: []KeyShareEntry{
				{Group: x25519, KeyExchange: make([]byte, 65536)},
			},
		}

		_, err := ks.Marshal()
		assert.ErrorIs(t, err, errInvalidKeyShareFormat)
	})
}

func TestKeyShare_Marshal_ServerHello(t *testing.T) {
	okShare := &KeyShareEntry{Group: secp384r1, KeyExchange: bytes.Repeat([]byte{0x42}, 48)}
	ks := &KeyShare{ServerShare: okShare}

	raw, err := ks.Marshal()
	assert.NoError(t, err)

	var parsed KeyShare
	err = parsed.Unmarshal(raw)
	assert.NoError(t, err)
	assert.Nil(t, parsed.ClientShares)
	assert.Nil(t, parsed.SelectedGroup)
	assert.NotNil(t, parsed.ServerShare)
	assert.Equal(t, okShare.Group, parsed.ServerShare.Group)
	assert.Equal(t, okShare.KeyExchange, parsed.ServerShare.KeyExchange)

	t.Run("invalid group", func(t *testing.T) {
		ks := &KeyShare{ServerShare: &KeyShareEntry{Group: 0x0001, KeyExchange: []byte{1}}}
		_, err := ks.Marshal()
		assert.ErrorIs(t, err, errInvalidKeyShareGroup)
	})

	t.Run("key len = 0", func(t *testing.T) {
		ks := &KeyShare{ServerShare: &KeyShareEntry{Group: x25519, KeyExchange: nil}}
		_, err := ks.Marshal()
		assert.ErrorIs(t, err, errInvalidKeyShareFormat)
	})

	t.Run("key len > 65535", func(t *testing.T) {
		ks := &KeyShare{ServerShare: &KeyShareEntry{Group: x25519, KeyExchange: make([]byte, 65536)}}
		_, err := ks.Marshal()
		assert.ErrorIs(t, err, errInvalidKeyShareFormat)
	})
}

func TestKeyShare_Marshal_HelloRetryRequest(t *testing.T) {
	group := NamedGroup(FFDHEPrivateStart) // valid private-use
	ks := &KeyShare{SelectedGroup: &group}

	raw, err := ks.Marshal()
	assert.NoError(t, err)

	var parsed KeyShare
	err = parsed.Unmarshal(raw)
	assert.NoError(t, err)
	assert.Nil(t, parsed.ClientShares)
	assert.Nil(t, parsed.ServerShare)
	if assert.NotNil(t, parsed.SelectedGroup) {
		assert.Equal(t, group, *parsed.SelectedGroup)
	}

	t.Run("invalid group", func(t *testing.T) {
		group := NamedGroup(0x0001)
		ks := &KeyShare{SelectedGroup: &group}
		_, err := ks.Marshal()
		assert.ErrorIs(t, err, errInvalidKeyShareGroup)
	})
}

func TestKeyShare_Marshal_MultipleContexts_Error(t *testing.T) {
	group := x25519
	ks := &KeyShare{
		ClientShares:  []KeyShareEntry{{Group: x25519, KeyExchange: []byte{1}}},
		ServerShare:   &KeyShareEntry{Group: secp256R1, KeyExchange: []byte{2}},
		SelectedGroup: &group,
	}

	_, err := ks.Marshal()
	assert.ErrorIs(t, err, errInvalidKeyShareFormat)
}

func TestKeyShare_Unmarshal_ClientHello(t *testing.T) {
	// client_shares = [x25519, 0x0001(invalid), secp521r1]
	var b cryptobyte.Builder
	typeValue := KeyShare{}.TypeValue()

	b.AddUint16(uint16(typeValue))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			addKeyShareEntry(b, KeyShareEntry{Group: x25519, KeyExchange: []byte{1}})

			// invalid group (ignored)
			b.AddUint16(uint16(0x0001))
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte{2}) })

			addKeyShareEntry(b, KeyShareEntry{Group: secp521r1, KeyExchange: []byte{3}})
		})
	})
	raw, _ := b.Bytes()

	var ks KeyShare
	err := ks.Unmarshal(raw)
	assert.NoError(t, err)
	assert.Nil(t, ks.ServerShare)
	assert.Nil(t, ks.SelectedGroup)

	if assert.Equal(t, 2, len(ks.ClientShares)) {
		assert.Equal(t, x25519, ks.ClientShares[0].Group)
		assert.Equal(t, []byte{1}, ks.ClientShares[0].KeyExchange)
		assert.Equal(t, secp521r1, ks.ClientShares[1].Group)
		assert.Equal(t, []byte{3}, ks.ClientShares[1].KeyExchange)
	}

	// sending duplicate valid groups should error
	var dup cryptobyte.Builder
	dup.AddUint16(uint16(typeValue))

	dup.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			addKeyShareEntry(b, KeyShareEntry{Group: x25519, KeyExchange: []byte{1}})
			addKeyShareEntry(b, KeyShareEntry{Group: x25519, KeyExchange: []byte{2}})
		})
	})

	rawDup, _ := dup.Bytes()

	err = ks.Unmarshal(rawDup)
	assert.ErrorIs(t, err, errDuplicateKeyShare)
}

func TestKeyShare_Unmarshal_ClientHello_TruncatedEntries(t *testing.T) {
	// bad ext: vecLen=1, then a single byte to force group uint16 read error.
	typeValue := KeyShare{}.TypeValue()
	raw := []byte{
		byte(uint16(typeValue) >> 8), byte(uint16(typeValue)), // type
		0x00, 0x03, // ext len = 3
		0x00, 0x01, // vecLen = 1
		0xFF, // only 1 byte, not enough for group uint16
	}

	var ks KeyShare
	err := ks.Unmarshal(raw)
	assert.ErrorIs(t, err, errInvalidKeyShareFormat)

	// bad ext 2: one full group but key_exchange length=1 with no bytes
	raw2 := []byte{
		byte(uint16(typeValue) >> 8), byte(uint16(typeValue)),
		0x00, 0x06, // ext len = 6 (2 vecLen + 4 bytes below)
		0x00, 0x04, // vecLen = 4
		0x00, 0x1D, // group x25519
		0x00, 0x01, // key len = 1 (but 0 bytes present) -> read fails
	}

	err = ks.Unmarshal(raw2)
	assert.ErrorIs(t, err, errInvalidKeyShareFormat)
}

func TestKeyShare_Unmarshal_HelloRetryRequest(t *testing.T) {
	typeValue := KeyShare{}.TypeValue()
	var okb cryptobyte.Builder
	okb.AddUint16(uint16(typeValue))

	okb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(uint16(secp384r1))
	})

	rawOK, _ := okb.Bytes()
	var ks KeyShare
	err := ks.Unmarshal(rawOK)
	assert.NoError(t, err)
	assert.NotNil(t, ks.SelectedGroup)
	assert.Equal(t, secp384r1, *ks.SelectedGroup)
	assert.Nil(t, ks.ServerShare)
	assert.Nil(t, ks.ClientShares)

	// invalid group in HelloRetryRequest
	var bad cryptobyte.Builder
	bad.AddUint16(uint16(typeValue))

	bad.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(uint16(0x0001))
	})

	rawBad, _ := bad.Bytes()
	err = ks.Unmarshal(rawBad)
	assert.ErrorIs(t, err, errInvalidKeyShareGroup)

	rawTrunc := []byte{byte(uint16(typeValue) >> 8), byte(uint16(typeValue)), 0x00, 0x01, 0x00}
	err = ks.Unmarshal(rawTrunc)
	assert.ErrorIs(t, err, errInvalidKeyShareFormat)
}

func TestKeyShare_Unmarshal_ServerHello(t *testing.T) {
	typeValue := KeyShare{}.TypeValue()

	var ok cryptobyte.Builder
	ok.AddUint16(uint16(typeValue))
	ok.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		addKeyShareEntry(b, KeyShareEntry{Group: ffdhe4096, KeyExchange: []byte{1, 2, 3}})
	})
	rawOK, _ := ok.Bytes()

	var ks KeyShare
	err := ks.Unmarshal(rawOK)
	assert.NoError(t, err)
	assert.NotNil(t, ks.ServerShare)
	assert.Equal(t, ffdhe4096, ks.ServerShare.Group)
	assert.Equal(t, []byte{1, 2, 3}, ks.ServerShare.KeyExchange)
	assert.Nil(t, ks.SelectedGroup)
	assert.Nil(t, ks.ClientShares)

	// Trailing extra bytes after server_share
	var trailing cryptobyte.Builder
	trailing.AddUint16(uint16(typeValue))

	trailing.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		addKeyShareEntry(b, KeyShareEntry{Group: x448, KeyExchange: []byte{9}})
		b.AddUint8(0x00) // extra bytes
	})

	rawTrailing, _ := trailing.Bytes()
	err = ks.Unmarshal(rawTrailing)
	assert.ErrorIs(t, err, errInvalidKeyShareFormat)

	// invalid group
	var badGroup cryptobyte.Builder
	badGroup.AddUint16(uint16(typeValue))

	badGroup.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(uint16(0x0001))
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte{1}) })
	})

	rawBadGroup, _ := badGroup.Bytes()
	err = ks.Unmarshal(rawBadGroup)
	assert.ErrorIs(t, err, errInvalidKeyShareGroup)

	// bad key length (claims 1, provides 0)
	rawBadLen := []byte{
		byte(uint16(typeValue) >> 8), byte(uint16(typeValue)),
		0x00, 0x04, // ext len matches the 4 bytes below
		0x00, 0x1D, // group x25519
		0x00, 0x01, // key len = 1, but 0 bytes provided -> format error
	}
	err = ks.Unmarshal(rawBadLen)
	assert.ErrorIs(t, err, errInvalidKeyShareFormat)
}

func TestKeyShare_Unmarshal_Errors(t *testing.T) {
	// wrong extension type
	var w cryptobyte.Builder
	w.AddUint16(0xFFFF)
	w.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
	rawWrong, _ := w.Bytes()
	var ks KeyShare
	err := ks.Unmarshal(rawWrong)
	assert.ErrorIs(t, err, errInvalidExtensionType)

	// buffer too small (no length field)
	var small cryptobyte.Builder
	small.AddUint16(uint16(KeyShare{}.TypeValue()))

	rawSmall, _ := small.Bytes()
	err = ks.Unmarshal(rawSmall)
	assert.ErrorIs(t, err, errBufferTooSmall)

	// empty extData
	var empty cryptobyte.Builder
	empty.AddUint16(uint16(KeyShare{}.TypeValue()))
	empty.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {})

	rawEmpty, _ := empty.Bytes()
	err = ks.Unmarshal(rawEmpty)
	assert.ErrorIs(t, err, errInvalidKeyShareFormat)
}

func Test_hasTooManyContexts(t *testing.T) {
	assert.False(t, hasTooManyContexts())                   // none
	assert.False(t, hasTooManyContexts(true, false, false)) // exactly one
	assert.False(t, hasTooManyContexts(false, true, false))
	assert.False(t, hasTooManyContexts(false, false, true))
	assert.True(t, hasTooManyContexts(true, true, false)) // two
	assert.True(t, hasTooManyContexts(true, false, true))
	assert.True(t, hasTooManyContexts(false, true, true))
	assert.True(t, hasTooManyContexts(true, true, true)) // three
}
