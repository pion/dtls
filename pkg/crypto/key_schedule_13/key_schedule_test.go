// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package keys_schedule_13

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHKDFExpandLabel_Simple(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, sha256.Size)
	ctx := []byte{0xAA, 0xBB}

	out, err := hkdfExpandLabel(secret, "client in", ctx, 16)
	assert.NoError(t, err)

	// Is there a way for us to have a fuzzy test to confirm this?
	assert.NotNil(t, out)
}

func TestHKDFLabel_Encoding_Shape(t *testing.T) {
	// ideally this should also be a fuzzy test, but maybe it would be overkill
	testStr := "key"

	secret := make([]byte, sha256.Size)
	_, err := hkdfExpandLabel(secret, testStr, nil, 32)
	assert.NoError(t, err)

	full := []byte(DTLS13prefix + testStr)

	assert.True(t, len(full) >= 7 && len(full) <= 255)
}

func TestHKDFLabel_Encoding_Shape_Label_Small(t *testing.T) {
	testStr := "" // 0 + 6 < 7, 6 is the length of the prefix

	secret := make([]byte, sha256.Size)
	_, err := hkdfExpandLabel(secret, testStr, nil, 32)
	assert.ErrorIs(t, errLabelTooSmall, err)

	full := []byte(DTLS13prefix + testStr)

	assert.False(t, len(full) >= 7 && len(full) <= 255)
	assert.Equal(t, 6, len(full))
}

func TestHKDFLabel_Encoding_Shape_Label_Big(t *testing.T) {
	testStr := strings.Repeat("a", 250) // 250 + 6 > 255, 6 is the length of the prefix

	secret := make([]byte, sha256.Size)
	_, err := hkdfExpandLabel(secret, testStr, nil, 32)
	assert.ErrorIs(t, errLabelTooBig, err)

	full := []byte(DTLS13prefix + testStr)

	assert.False(t, len(full) >= 7 && len(full) <= 255)
	assert.Equal(t, 256, len(full))
}

func TestHKDFLabel_Encoding_Shape_Context_Length_Zero(t *testing.T) {
	validLabel := "hi"
	zeroContext := bytes.NewBufferString("").Bytes()

	secret := make([]byte, sha256.Size)
	_, err := hkdfExpandLabel(secret, validLabel, zeroContext, 32)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(zeroContext))
}

func TestHKDFLabel_Encoding_Shape_Context_Too_Big(t *testing.T) {
	validLabel := "hi"
	secret := make([]byte, sha256.Size)

	// from bytes
	invalidContext := bytes.Repeat([]byte{1}, 256)

	_, err := hkdfExpandLabel(secret, validLabel, invalidContext, 32)
	assert.ErrorIs(t, errContextTooBig, err)
	assert.Equal(t, 256, len(invalidContext))

	// from string
	invalidContext = bytes.NewBufferString(strings.Repeat("a", 256)).Bytes()

	_, err = hkdfExpandLabel(secret, validLabel, invalidContext, 32)
	assert.ErrorIs(t, errContextTooBig, err)
	assert.Equal(t, 256, len(invalidContext))
}

// note: these these tests are basically a copy of the first two tests
func TestDeriveSecret(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, sha256.Size)
	ctx := []byte{0xAA, 0xBB}

	out, err := deriveSecret(secret, "client in", ctx)
	assert.NoError(t, err)

	// Is there a way for us to have a fuzzy test to confirm this?
	assert.NotNil(t, out)
}

func TestDeriveSecret_Encoding_Shape(t *testing.T) {
	// ideally this should also be a fuzzy test, but maybe it would be overkill
	testStr := "key"

	secret := make([]byte, sha256.Size)
	_, err := deriveSecret(secret, testStr, nil)
	assert.NoError(t, err)

	full := []byte(DTLS13prefix + testStr)

	assert.True(t, len(full) >= 7 && len(full) <= 255)
}
