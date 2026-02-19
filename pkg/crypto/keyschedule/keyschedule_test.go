// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package keyschedule

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// RFC 5869 Appendix A.1 (Test Case 1, SHA-256).
func TestHKDFExtract_SHA256_VectorA1(t *testing.T) {
	// IKM = 0x0b repeated 22 bytes (RFC 5869 A.1)
	ikm := bytes.Repeat([]byte{0x0b}, 22)

	// salt = 0x000102030405060708090a0b0c (RFC 5869 A.1)
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")

	// PRK expected (RFC 5869 A.1)
	expected, _ := hex.DecodeString("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

	actual, err := HkdfExtract(sha256.New, salt, ikm)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestHKDFExtract_Nil_Hash_Error(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")

	_, err := HkdfExtract(nil, salt, ikm)
	assert.ErrorIs(t, errMissingHashFunction, err)
}

func TestHKDFExpandLabel_Simple(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, sha256.Size)
	ctx := []byte{0xAA, 0xBB}

	out, err := HkdfExpandLabel(sha256.New, secret, "client in", ctx, 16)
	assert.NoError(t, err)
	assert.NotNil(t, out)
}

func TestHKDFLabel_Encoding_Shape(t *testing.T) {
	testStr := "key"

	secret := make([]byte, sha256.Size)
	_, err := HkdfExpandLabel(sha256.New, secret, testStr, nil, 32)
	assert.NoError(t, err)
}

func TestHKDFLabel_Encoding_Shape_Label_Small(t *testing.T) {
	testStr := "" // 0 + 6 < 7, 6 is the length of the prefix

	secret := make([]byte, sha256.Size)
	_, err := HkdfExpandLabel(sha256.New, secret, testStr, nil, 32)
	assert.ErrorIs(t, errLabelTooSmall, err)
}

func TestHKDFLabel_Encoding_Shape_Label_Big(t *testing.T) {
	testStr := strings.Repeat("a", 250) // 250 + 6 > 255, 6 is the length of the prefix

	secret := make([]byte, sha256.Size)
	_, err := HkdfExpandLabel(sha256.New, secret, testStr, nil, 32)
	assert.ErrorIs(t, errLabelTooBig, err)
}

func TestHKDFLabel_Encoding_Shape_Context_Length_Zero(t *testing.T) {
	validLabel := "hi"
	zeroContext := bytes.NewBufferString("").Bytes()

	secret := make([]byte, sha256.Size)
	_, err := HkdfExpandLabel(sha256.New, secret, validLabel, zeroContext, 32)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(zeroContext))
}

func TestHKDFLabel_Encoding_Shape_Context_Too_Big(t *testing.T) {
	validLabel := "hi"
	secret := make([]byte, sha256.Size)

	invalidContext := bytes.Repeat([]byte{1}, 256)

	_, err := HkdfExpandLabel(sha256.New, secret, validLabel, invalidContext, 32)
	assert.ErrorIs(t, errContextTooBig, err)
	assert.Equal(t, 256, len(invalidContext))

	invalidContext = bytes.NewBufferString(strings.Repeat("a", 256)).Bytes()

	_, err = HkdfExpandLabel(sha256.New, secret, validLabel, invalidContext, 32)
	assert.ErrorIs(t, errContextTooBig, err)
	assert.Equal(t, 256, len(invalidContext))
}

func TestDeriveSecret(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, sha256.Size)
	ctx := []byte{0xAA, 0xBB}

	transcript := sha256.New()
	transcript.Write(ctx)

	out, err := DeriveSecret(sha256.New, secret, "client in", transcript)
	assert.NoError(t, err)
	assert.NotNil(t, out)
}

func TestDeriveSecret_Empty_Transcript(t *testing.T) {
	testStr := "key"

	secret := make([]byte, sha256.Size)
	_, err := DeriveSecret(sha256.New, secret, testStr, nil)
	assert.NoError(t, err)
}
