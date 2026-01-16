// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPreSharedKeyServerHello(t *testing.T) {
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

func TestPreSharedKeyClientHello(t *testing.T) {
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
