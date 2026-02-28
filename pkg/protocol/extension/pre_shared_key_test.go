// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/cryptobyte"
)

func TestPreSharedKey_ServerHello(t *testing.T) {
	raw := []byte{
		0x00, 0x29, // extension type
		0x00, 0x02, // extension length
		0x01, 0x42, // selected_identity
	}

	extension := PreSharedKey{}

	expect := PreSharedKey{SelectedIdentity: 0x142}

	assert.NoError(t, extension.Unmarshal(raw))
	assert.Equal(t, expect.SelectedIdentity, extension.SelectedIdentity)

	test, err := expect.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, raw, test)
}

func TestPreSharedKey_ClientHello(t *testing.T) {
	binder := make([]byte, 32)
	for i := range binder {
		binder[i] = byte(i)
	}

	raw := []byte{
		0x00, 0x29, // extension type
		0x00, 0x2d, // extension length
		0x00, 0x08, // identities length
		0x00, 0x02, // identity length
		0x42, 0x42, // identity
		0xff, 0xff, // ticket_age
		0xff, 0xff, // ticket_age
		0x00, 0x21, // binders length
		0x20, // binder entry legnth
	}

	raw = append(raw, binder...)

	extension := PreSharedKey{}

	expectIdentity := PskIdentity{Identity: []byte{0x42, 0x42}, ObfuscatedTicketAge: uint32(0xffffffff)}
	expect := PreSharedKey{Identities: []PskIdentity{expectIdentity}, Binders: []PskBinderEntry{binder}}

	assert.NoError(t, extension.Unmarshal(raw))
	assert.Equal(t, uint16(0), extension.SelectedIdentity)
	assert.Equal(t, 1, len(extension.Identities))
	assert.Equal(t, expect.Identities[0], extension.Identities[0])
	assert.Equal(t, 1, len(extension.Binders))
	assert.Equal(t, expect.Binders[0], extension.Binders[0])

	test, err := expect.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, raw, test)
}

func TestPreSharedKey_ClientHello_EmptyIdentities(t *testing.T) {
	binder := make([]byte, 32)
	for i := range binder {
		binder[i] = byte(i)
	}

	raw := []byte{
		0x00, 0x29, // extension type
		0x00, 0x2b, // extension length
		0x00, 0x06, // identities length
		0x00, 0x00, // identity length
		0xff, 0xff, // ticket_age
		0xff, 0xff, // ticket_age
		0x00, 0x21, // binders length
		0x20, // binder entry legnth
	}

	raw = append(raw, binder...)

	extension := PreSharedKey{}

	err := extension.Unmarshal(raw)
	assert.ErrorIs(t, err, errPreSharedKeyFormat)
}

func TestPreSharedKey_ClientHello_MultipleIdentities(t *testing.T) {
	binder := make([]byte, 32)
	for i := range binder {
		binder[i] = byte(i)
	}

	raw := []byte{
		0x00, 0x29, // extension type
		0x00, 0x56, // extension length
		0x00, 0x10, // identities length
		0x00, 0x02, // identity length
		0x41, 0x41, // identity
		0xaa, 0xaa, // ticket_age
		0xaa, 0xaa, // ticket_age
		0x00, 0x02, // identity length
		0x42, 0x42, // identity
		0xff, 0xff, // ticket_age
		0xff, 0xff, // ticket_age
		0x00, 0x42, // binders length
		0x20, // binder entry legnth
	}

	raw = append(raw, binder...)
	raw = append(raw, []byte{0x20}...)
	raw = append(raw, binder...)

	extension := PreSharedKey{}

	expectIdentity1 := PskIdentity{
		Identity:            []byte{0x41, 0x41},
		ObfuscatedTicketAge: uint32(0xaaaaaaaa),
	}
	expectIdentity2 := PskIdentity{
		Identity:            []byte{0x42, 0x42},
		ObfuscatedTicketAge: uint32(0xffffffff),
	}

	expect := PreSharedKey{
		Identities: []PskIdentity{
			expectIdentity1,
			expectIdentity2,
		},
		Binders: []PskBinderEntry{
			binder,
			binder,
		},
	}

	assert.NoError(t, extension.Unmarshal(raw))
	assert.Equal(t, uint16(0), extension.SelectedIdentity)
	assert.Equal(t, 2, len(extension.Identities))
	assert.Equal(t, expect.Identities[0], extension.Identities[0])
	assert.Equal(t, expect.Identities[1], extension.Identities[1])
	assert.Equal(t, 2, len(extension.Binders))
	assert.Equal(t, expect.Binders[0], extension.Binders[0])
	assert.Equal(t, expect.Binders[1], extension.Binders[1])

	test, err := expect.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, raw, test)
}

func TestPreSharedKey_ClientHello_MultipleIdentities_SingleBinder(t *testing.T) {
	binder := make([]byte, 32)
	for i := range binder {
		binder[i] = byte(i)
	}

	raw := []byte{
		0x00, 0x29, // extension type
		0x00, 0x0a, // extension length
		0x00, 0x10, // identities length
		0x00, 0x02, // identity length
		0x41, 0x41, // identity
		0xaa, 0xaa, // ticket_age
		0xaa, 0xaa, // ticket_age
		0x00, 0x02, // identity length
		0x42, 0x42, // identity
		0xff, 0xff, // ticket_age
		0xff, 0xff, // ticket_age
		0x00, 0x42, // binders length
		0x20, // binder entry legnth
	}

	raw = append(raw, binder...)

	extension := PreSharedKey{}

	err := extension.Unmarshal(raw)
	assert.ErrorIs(t, err, errPreSharedKeyFormat)
}

func TestPreSharedKey_ClientHello_LowBinders(t *testing.T) {
	binder := make([]byte, 16)
	for i := range binder {
		binder[i] = byte(i)
	}
	raw := []byte{
		0x00, 0x29, // extension type
		0x00, 0x0a, // extension length
		0x00, 0x06, // identities length
		0x00, 0x02, // identity length
		0x42, 0x42, // identity
		0xff, 0xff, // ticket_age
		0xff, 0xff, // ticket_age
		0x00, 0x11, // binders length
		0x10, // binder entry legnth
	}
	raw = append(raw, binder...)

	extension := PreSharedKey{}

	err := extension.Unmarshal(raw)
	assert.ErrorIs(t, err, errPreSharedKeyFormat)
}

func FuzzPreSharedKeyUnmarshal(f *testing.F) {
	binder := make([]byte, 32)
	for i := range binder {
		binder[i] = byte(i)
	}

	rawCH := []byte{
		0x00, 0x29, // extension type
		0x00, 0x2d, // extension length
		0x00, 0x08, // identities length
		0x00, 0x02, // identity length
		0x42, 0x42, // identity
		0xff, 0xff, // ticket_age
		0xff, 0xff, // ticket_age
		0x00, 0x21, // binders length
		0x20, // binder entry legnth
	}

	rawCH = append(rawCH, binder...)

	testcases := [][]byte{
		{
			0x00, 0x29, // extension type
			0x00, 0x02, // extension length
			0x01, 0x42, // selected_identity
		},
		rawCH,
	}

	for _, tc := range testcases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, a []byte) {
		psk := PreSharedKey{}
		err := psk.Unmarshal(a)
		if err == nil {
			// ServerHello
			if len(a) == 6 && len(psk.Identities) != 0 && len(psk.Binders) != 0 {
				assert.Fail(t, "PreSharedKey was unmarshalled without error both as ServerHello and ClientHello")
			}

			// ClientHello
			data := cryptobyte.String(a[2:3])
			var length uint16
			data.ReadUint16(&length)
			if length > 2 {
				assert.NotZero(t, len(psk.Identities))
				assert.NotZero(t, len(psk.Binders))
				assert.Equal(t, len(psk.Binders), len(psk.Binders))
			}
		}
	})
}
