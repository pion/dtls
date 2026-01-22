// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
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
	// X25519 public key
	p1 := []byte{
		0xa8, 0xf1, 0xb7, 0x2d, 0x70, 0x7e, 0x58, 0xa4, 0x41, 0x73, 0x9e, 0x21,
		0x7b, 0x62, 0x1e, 0xd1, 0x4d, 0x11, 0x69, 0xa6, 0xbf, 0x72, 0x21, 0xec,
		0xaf, 0x76, 0xf3, 0x4e, 0xec, 0x48, 0x52, 0x1,
	}
	// P-256 uncompressed point
	p2 := []byte{
		0x4, 0xc5, 0xf5, 0xee, 0xf0, 0x1f, 0x4d, 0x53, 0xa6, 0x42, 0xd8, 0x3b,
		0x3a, 0x40, 0x48, 0x22, 0x49, 0x7f, 0x1a, 0xc7, 0xce, 0x66, 0x85, 0xfb,
		0xc9, 0x91, 0x9d, 0x7f, 0x72, 0xce, 0x88, 0x30, 0xc3, 0x3d, 0x5, 0x4c,
		0x5f, 0x7a, 0xaa, 0x9d, 0xcf, 0x3b, 0x44, 0x2a, 0xc0, 0xc9, 0x9f, 0x3,
		0x2b, 0x5, 0x5b, 0xbb, 0x9c, 0x5d, 0x7f, 0xf9, 0x24, 0x51, 0x4b, 0xab,
		0x36, 0xce, 0x46, 0x55, 0x7b,
	}

	ks := &KeyShare{
		ClientShares: []KeyShareEntry{
			{Group: elliptic.X25519, KeyExchange: p1},
			{Group: elliptic.P256, KeyExchange: p2},
		},
	}

	raw, err := ks.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x0, 0x33, // extension type
		0x0, 0x6b, // extension length
		0x0, 0x69, // vec length
		0x0, 0x1d, // X25519
		0x0, 0x20, // length 32
		0xa8, 0xf1, 0xb7, 0x2d, 0x70, 0x7e, 0x58, 0xa4, 0x41, 0x73, 0x9e, 0x21,
		0x7b, 0x62, 0x1e, 0xd1, 0x4d, 0x11, 0x69, 0xa6, 0xbf, 0x72, 0x21, 0xec,
		0xaf, 0x76, 0xf3, 0x4e, 0xec, 0x48, 0x52, 0x1,
		0x0, 0x17, // P-256
		0x0, 0x41, // length 65
		0x4, 0xc5, 0xf5, 0xee, 0xf0, 0x1f, 0x4d, 0x53, 0xa6, 0x42, 0xd8, 0x3b,
		0x3a, 0x40, 0x48, 0x22, 0x49, 0x7f, 0x1a, 0xc7, 0xce, 0x66, 0x85, 0xfb,
		0xc9, 0x91, 0x9d, 0x7f, 0x72, 0xce, 0x88, 0x30, 0xc3, 0x3d, 0x5, 0x4c,
		0x5f, 0x7a, 0xaa, 0x9d, 0xcf, 0x3b, 0x44, 0x2a, 0xc0, 0xc9, 0x9f, 0x3,
		0x2b, 0x5, 0x5b, 0xbb, 0x9c, 0x5d, 0x7f, 0xf9, 0x24, 0x51, 0x4b, 0xab,
		0x36, 0xce, 0x46, 0x55, 0x7b,
	}

	assert.Equal(t, expect, raw)
}

func TestKeyShare_Marshal_ClientHello_Errors(t *testing.T) {
	t.Run("duplicate group", func(t *testing.T) {
		ks := &KeyShare{
			ClientShares: []KeyShareEntry{
				{Group: elliptic.X25519, KeyExchange: []byte{1}},
				{Group: elliptic.X25519, KeyExchange: []byte{2}},
			},
		}

		_, err := ks.Marshal()
		assert.ErrorIs(t, err, errDuplicateKeyShare)
	})

	t.Run("key len = 0", func(t *testing.T) {
		ks := &KeyShare{
			ClientShares: []KeyShareEntry{
				{Group: elliptic.X25519, KeyExchange: nil},
			},
		}

		_, err := ks.Marshal()
		assert.ErrorIs(t, err, errInvalidKeyShareFormat)
	})

	t.Run("key len > 65535", func(t *testing.T) {
		ks := &KeyShare{
			ClientShares: []KeyShareEntry{
				{Group: elliptic.X25519, KeyExchange: make([]byte, 65536)},
			},
		}

		_, err := ks.Marshal()
		assert.ErrorIs(t, err, errInvalidKeyShareFormat)
	})
}

func TestKeyShare_Marshal_ServerHello_OK(t *testing.T) {
	// X25519 public key
	p1 := []byte{
		0xa8, 0xf1, 0xb7, 0x2d, 0x70, 0x7e, 0x58, 0xa4, 0x41, 0x73,
		0x9e, 0x21, 0x7b, 0x62, 0x1e, 0xd1, 0x4d, 0x11, 0x69, 0xa6, 0xbf, 0x72,
		0x21, 0xec, 0xaf, 0x76, 0xf3, 0x4e, 0xec, 0x48, 0x52, 0x1,
	}
	okShare := KeyShareEntry{Group: elliptic.X25519, KeyExchange: p1}
	ks := &KeyShare{ServerShare: &okShare}

	raw, err := ks.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x0, 0x33, // extension type
		0x0, 0x24, // extension length
		0x0, 0x1d, // X25519
		0x0, 0x20, // length 32
		0xa8, 0xf1, 0xb7, 0x2d, 0x70, 0x7e, 0x58, 0xa4, 0x41, 0x73, 0x9e, 0x21,
		0x7b, 0x62, 0x1e, 0xd1, 0x4d, 0x11, 0x69, 0xa6, 0xbf, 0x72, 0x21, 0xec,
		0xaf, 0x76, 0xf3, 0x4e, 0xec, 0x48, 0x52, 0x1,
	}

	assert.Equal(t, expect, raw)
}

func TestKeyShare_Marshal_HelloRetryRequest(t *testing.T) {
	group := elliptic.P384
	ks := &KeyShare{SelectedGroup: &group}

	raw, err := ks.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x0, 0x33, // extension type
		0x0, 0x2, // extension length
		0x0, 0x18, // P-384
	}

	assert.Equal(t, expect, raw)
}

func TestKeyShare_Marshal_MultipleContexts_Error(t *testing.T) {
	group := elliptic.X25519
	ks := &KeyShare{
		ClientShares:  []KeyShareEntry{{Group: group, KeyExchange: []byte{1}}},
		ServerShare:   &KeyShareEntry{Group: group, KeyExchange: []byte{2}},
		SelectedGroup: &group,
	}

	_, err := ks.Marshal()
	assert.ErrorIs(t, err, errInvalidKeyShareFormat)
}

func TestKeyShare_Unmarshal_ClientHello(t *testing.T) {
	raw := []byte{
		0x0, 0x33, // extension type
		0x0, 0x11, // extension length
		0x0, 0xf, // vec length
		0x0, 0x1d, // X25519
		0x0, 0x1, // group length
		0x41,
		0x11, 0xff, // Non-supported group
		0x0, 0x1, // group length
		0x42,
		0x0, 0x18, // P-384
		0x0, 0x1, // group length
		0x43,
	}

	var ks KeyShare
	err := ks.Unmarshal(raw)
	assert.NoError(t, err)
	assert.Nil(t, ks.ServerShare)
	assert.Nil(t, ks.SelectedGroup)

	if assert.Equal(t, 3, len(ks.ClientShares)) {
		assert.Equal(t, elliptic.X25519, ks.ClientShares[0].Group)
		assert.Equal(t, []byte{0x41}, ks.ClientShares[0].KeyExchange)
		assert.Equal(t, elliptic.Curve(0x11ff), ks.ClientShares[1].Group)
		assert.Equal(t, []byte{0x42}, ks.ClientShares[1].KeyExchange)
		assert.Equal(t, elliptic.P384, ks.ClientShares[2].Group)
		assert.Equal(t, []byte{0x43}, ks.ClientShares[2].KeyExchange)
	}

	// zero length keyshare vector should throw error
	rawZero := []byte{
		0x0, 0x33, // extension type
		0x0, 0x7, // extension length
		0x0, 0x5, // vec length
		0x0, 0x1d, // X25519
		0x0, 0x0, // group length
		0x42,
	}

	err = ks.Unmarshal(rawZero)
	assert.ErrorIs(t, err, errInvalidKeyShareFormat)

	// sending duplicate valid groups should error
	rawDup := []byte{
		0x0, 0x33, // extension type
		0x0, 0x11, // extension length
		0x0, 0xf, // vec length
		0x0, 0x1d, // X25519
		0x0, 0x1, // group length
		0x41,
		0x0, 0x1d, // Non-supported group
		0x0, 0x1, // group length
		0x42,
		0x0, 0x18, // P-384
		0x0, 0x1, // group length
		0x43,
	}

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
	raw := []byte{
		0x0, 0x33, // extension type
		0x0, 0x2, // extension length
		0x0, 0x1d, // X25519
	}

	var ks KeyShare
	err := ks.Unmarshal(raw)
	assert.NoError(t, err)
	assert.NotNil(t, ks.SelectedGroup)
	assert.Equal(t, elliptic.X25519, *ks.SelectedGroup)
	assert.Nil(t, ks.ServerShare)
	assert.Nil(t, ks.ClientShares)

	// Unsupported group in HelloRetryRequest
	raw2 := []byte{
		0x0, 0x33, // extension type
		0x0, 0x2, // extension length
		0x0, 0x1, // unsupported group
	}

	err = ks.Unmarshal(raw2)
	assert.NoError(t, err)
	assert.Nil(t, ks.SelectedGroup)

	ks.TypeValue()
	rawTrunc := []byte{byte(uint16(typeValue) >> 8), byte(uint16(typeValue)), 0x00, 0x01, 0x00}
	err = ks.Unmarshal(rawTrunc)
	assert.ErrorIs(t, err, errInvalidKeyShareFormat)
}

func TestKeyShare_Unmarshal_ServerHello(t *testing.T) {
	typeValue := KeyShare{}.TypeValue()

	raw := []byte{
		0x0, 0x33, // extension type
		0x0, 0x06, // extension length
		0x0, 0x1d, // X25519
		0x0, 0x2, // group length
		0x41, 0x42,
	}

	var ks KeyShare
	err := ks.Unmarshal(raw)
	assert.NoError(t, err)
	assert.Nil(t, ks.SelectedGroup)
	assert.Nil(t, ks.ClientShares)
	assert.NotNil(t, ks.ServerShare)
	assert.Equal(t, elliptic.X25519, ks.ServerShare.Group)
	assert.Equal(t, []byte{0x41, 0x42}, ks.ServerShare.KeyExchange)

	// Trailing extra bytes after key_share
	rawTrailing := []byte{
		0x0, 0x33, // extension type
		0x0, 0x08, // extension length
		0x0, 0x1d, // X25519
		0x0, 0x2, // group length
		0x41, 0x42,
		0x43, 0x44,
	}

	err = ks.Unmarshal(rawTrailing)
	assert.ErrorIs(t, err, errInvalidKeyShareFormat)

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
	assert.False(t, hasTooManyContexts(false, false, false))
	assert.False(t, hasTooManyContexts(true, false, false)) // exactly one
	assert.False(t, hasTooManyContexts(false, true, false))
	assert.False(t, hasTooManyContexts(false, false, true))
	assert.True(t, hasTooManyContexts(true, true, false)) // two
	assert.True(t, hasTooManyContexts(true, false, true))
	assert.True(t, hasTooManyContexts(false, true, true))
	assert.True(t, hasTooManyContexts(true, true, true)) // three
}
